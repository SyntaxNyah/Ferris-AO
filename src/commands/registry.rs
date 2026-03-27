use std::sync::Arc;

use crate::{
    auth::accounts::perms,
    client::ClientSession,
    game::areas::{LockState, Status},
    protocol::packet::ao_encode,
    server::ServerState,
};

/// Dispatch an OOC command (parsed from a `/cmd args` string).
/// All commands are async-capable via the runtime handle.
pub async fn dispatch_command(
    session: &mut ClientSession,
    state: &Arc<ServerState>,
    command: &str,
    args: Vec<String>,
) {
    match command {
        "help" | "h" => cmd_help(session, state),
        "about" => cmd_about(session, state),
        "who" => cmd_who(session, state).await,
        "move" => cmd_move(session, state, args).await,
        "charselect" => cmd_charselect(session, state).await,
        "doc" => cmd_doc(session, state, args).await,
        "areainfo" => cmd_areainfo(session, state).await,
        "cm" => cmd_cm(session, state, args).await,
        "uncm" => cmd_uncm(session, state, args).await,
        "bg" => cmd_bg(session, state, args).await,
        "status" => cmd_status(session, state, args).await,
        "lock" => cmd_lock(session, state, args).await,
        "unlock" => cmd_unlock(session, state).await,
        "play" => cmd_play(session, state, args).await,
        "narrator" => cmd_narrator(session, state),
        "login" => cmd_login(session, state, args).await,
        "logout" => cmd_logout(session, state),
        "mod" => cmd_mod(session, state, args).await,
        "kick" => cmd_kick(session, state, args).await,
        "mute" => cmd_mute(session, state, args).await,
        "unmute" => cmd_unmute(session, state, args).await,
        "warn" => cmd_warn(session, state, args).await,
        "ban" => cmd_ban(session, state, args).await,
        "unban" => cmd_unban(session, state, args).await,
        "baninfo" => cmd_baninfo(session, state, args).await,
        "announce" => cmd_announce(session, state, args).await,
        "modchat" => cmd_modchat(session, state, args).await,
        "pair" => cmd_pair(session, state, args).await,
        "unpair" => cmd_unpair(session, state).await,
        "motd" => cmd_motd(session, state),
        "clear" => cmd_clear(session, state).await,
        _ => {
            session.server_message(&state.config.server.name, &format!("Unknown command: /{}", command));
        }
    }
}

fn cmd_help(session: &mut ClientSession, state: &Arc<ServerState>) {
    let msg = "\
Commands:
/help /about /who /move <area> /charselect /doc [text] /areainfo
/cm [uid] /uncm [uid] /bg <bg> /status <status> /lock [-s] /unlock /play <song>
/pair <uid> /unpair /narrator /login <user> <pass> /logout /mod <msg>
[MOD] /kick <uid> /mute <uid> [ic|ooc|all] /unmute <uid> /warn <uid> <reason>
[MOD] /ban <uid> <reason> /unban <ban_id> /baninfo <hdid_hash> /announce <msg> /modchat <msg>
/motd /clear";
    session.server_message(&state.config.server.name, msg);
}

fn cmd_about(session: &mut ClientSession, state: &Arc<ServerState>) {
    session.server_message(&state.config.server.name, &format!("NyahAO v0.1.0 - Privacy-first AO2 server"));
}

async fn cmd_who(session: &mut ClientSession, state: &Arc<ServerState>) {
    let clients = state.clients.lock().await;
    let count = clients.len();
    let list: Vec<String> = clients.values().map(|h| {
        let char_name = h.char_id
            .and_then(|id| state.characters.get(id))
            .map(|s| s.as_str())
            .unwrap_or("Spectator");
        format!("[{}] {}", h.uid, char_name)
    }).collect();
    drop(clients);
    session.server_message(
        &state.config.server.name,
        &format!("Players ({}/{}): {}", count, state.config.server.max_players, list.join(", ")),
    );
}

async fn cmd_move(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /move <area name or number>");
        return;
    }
    let target = args.join(" ");
    let idx = if let Ok(n) = target.parse::<usize>() {
        if n < state.areas.len() { Some(n) } else { None }
    } else {
        state.areas.iter().enumerate().find(|(_, a)| {
            // SAFETY: we hold a read future but not a lock; we need a blocking check.
            // For simplicity, match by iterating
            false // placeholder - resolved below
        }).map(|(i, _)| i)
    };

    // Name-based lookup
    let idx = if let Ok(n) = target.parse::<usize>() {
        if n < state.areas.len() { Some(n) } else { None }
    } else {
        let mut found = None;
        for (i, area_arc) in state.areas.iter().enumerate() {
            let area = area_arc.read().await;
            if area.name.to_lowercase() == target.to_lowercase() {
                found = Some(i);
                break;
            }
        }
        found
    };

    match idx {
        None => {
            session.server_message(&state.config.server.name, "Area not found.");
        }
        Some(new_idx) if new_idx == session.area_idx => {
            session.server_message(&state.config.server.name, "You are already in that area.");
        }
        Some(new_idx) => {
            let can_enter = {
                let area = state.areas[new_idx].read().await;
                if area.lock == LockState::Locked {
                    let uid = session.uid.unwrap_or(0);
                    area.invited.contains(&uid) || perms::has(session.permissions, perms::BYPASS_LOCK)
                } else {
                    true
                }
            };
            if !can_enter {
                session.server_message(&state.config.server.name, "You are not invited to that area.");
                return;
            }
            change_area(session, state, new_idx).await;
        }
    }
}

/// Core area change logic. Handles char release, re-join, ARUP updates.
pub async fn change_area(session: &mut ClientSession, state: &Arc<ServerState>, new_idx: usize) {
    let old_idx = session.area_idx;
    let uid = session.uid.unwrap_or(0);

    // Leave old area
    {
        let mut old_area = state.areas[old_idx].write().await;
        if let Some(char_id) = session.char_id {
            old_area.release_char(char_id);
        }
        old_area.players = old_area.players.saturating_sub(1);
        if old_area.players == 0 {
            old_area.reset();
        } else if old_area.has_cm(uid) {
            old_area.remove_cm(uid);
        }
    }

    // Update client handle area_idx
    {
        let mut clients = state.clients.lock().await;
        if let Some(handle) = clients.get_mut(&uid) {
            let handle = Arc::make_mut(handle);
            handle.area_idx = new_idx;
        }
    }

    session.area_idx = new_idx;

    // Join new area - check if char is taken
    {
        let mut new_area = state.areas[new_idx].write().await;
        if let Some(char_id) = session.char_id {
            if new_area.is_taken(char_id) {
                session.char_id = None;
                // Update client handle
            }
            if let Some(char_id) = session.char_id {
                new_area.taken[char_id] = true;
            }
        }
        new_area.players += 1;

        // Send area join info
        let taken = new_area.taken_strings();
        let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
        session.send_packet("CharsCheck", &taken_refs);
        session.send_packet("HP", &["1", &new_area.def_hp.to_string()]);
        session.send_packet("HP", &["2", &new_area.pro_hp.to_string()]);
        session.send_packet("BN", &[&new_area.bg.clone()]);

        let evi = new_area.evidence.clone();
        let evi_refs: Vec<&str> = evi.iter().map(|s| s.as_str()).collect();
        session.send_packet("LE", &evi_refs);
    }

    if session.char_id.is_none() {
        session.send_packet("DONE", &[]);
    } else {
        // Broadcast chars check to area
        let new_area = state.areas[new_idx].read().await;
        let taken = new_area.taken_strings();
        let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
        let msg = format!("CharsCheck#{}#%", taken_refs.join("#"));
        drop(new_area);
        state.broadcast_to_area(new_idx, "CharsCheck", &taken_refs).await;
    }

    let area_name = {
        let a = state.areas[new_idx].read().await;
        a.name.clone()
    };
    session.server_message(
        &state.config.server.name,
        &format!("Moved to {}.", area_name),
    );

    // ARUP
    state.send_player_arup().await;
    state.send_cm_arup().await;
    state.send_lock_arup().await;
    state.send_status_arup().await;
}

async fn cmd_charselect(session: &mut ClientSession, state: &Arc<ServerState>) {
    // Release current character and send DONE to put client back at char select
    if let Some(char_id) = session.char_id.take() {
        let mut area = state.areas[session.area_idx].write().await;
        area.release_char(char_id);
        let taken = area.taken_strings();
        let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
        drop(area);
        state.broadcast_to_area(session.area_idx, "CharsCheck", &taken_refs).await;
    }
    session.send_packet("DONE", &[]);
}

async fn cmd_doc(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if args.is_empty() {
        let area = state.areas[session.area_idx].read().await;
        let doc = if area.doc.is_empty() { "No document set.".to_string() } else { area.doc.clone() };
        session.server_message(&state.config.server.name, &format!("Document: {}", doc));
    } else {
        let doc_text = args.join(" ");
        let mut area = state.areas[session.area_idx].write().await;
        area.doc = doc_text.clone();
        session.server_message(&state.config.server.name, &format!("Document set to: {}", doc_text));
    }
}

async fn cmd_areainfo(session: &mut ClientSession, state: &Arc<ServerState>) {
    let area = state.areas[session.area_idx].read().await;
    let info = format!(
        "Area: {} | BG: {} | Players: {} | Status: {} | Lock: {} | Iniswap: {} | Music lock: {}",
        area.name, area.bg, area.players,
        area.status.as_str(), area.lock.as_str(),
        area.allow_iniswap, area.lock_music,
    );
    session.server_message(&state.config.server.name, &info);
}

async fn cmd_cm(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let uid = session.uid.unwrap_or(0);
    {
        let area = state.areas[session.area_idx].read().await;
        if !area.allow_cms && !perms::has(session.permissions, perms::CM) {
            session.server_message(&state.config.server.name, "CMs are not allowed in this area.");
            return;
        }
    }
    let target_uid = if args.is_empty() {
        uid
    } else {
        match args[0].parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                session.server_message(&state.config.server.name, "Usage: /cm [uid]");
                return;
            }
        }
    };
    {
        let mut area = state.areas[session.area_idx].write().await;
        area.add_cm(target_uid);
    }
    session.server_message(&state.config.server.name, &format!("UID {} is now a CM.", target_uid));
    state.send_cm_arup().await;
}

async fn cmd_uncm(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let uid = session.uid.unwrap_or(0);
    let is_cm = {
        let area = state.areas[session.area_idx].read().await;
        area.has_cm(uid)
    };
    if !is_cm && !perms::has(session.permissions, perms::CM) {
        session.server_message(&state.config.server.name, "You are not a CM in this area.");
        return;
    }
    let target_uid = if args.is_empty() {
        uid
    } else {
        match args[0].parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                session.server_message(&state.config.server.name, "Usage: /uncm [uid]");
                return;
            }
        }
    };
    {
        let mut area = state.areas[session.area_idx].write().await;
        area.remove_cm(target_uid);
    }
    state.send_cm_arup().await;
}

async fn cmd_bg(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let is_cm = {
        let area = state.areas[session.area_idx].read().await;
        area.has_cm(session.uid.unwrap_or(0))
    };
    if !is_cm && !perms::has(session.permissions, perms::MODIFY_AREA) {
        session.server_message(&state.config.server.name, "You must be a CM to change the background.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /bg <background name>");
        return;
    }
    let bg = args.join(" ");
    {
        let area = state.areas[session.area_idx].read().await;
        if area.lock_bg && !perms::has(session.permissions, perms::MODIFY_AREA) {
            session.server_message(&state.config.server.name, "The background is locked in this area.");
            return;
        }
        if area.force_bglist && !state.backgrounds.contains(&bg) {
            session.server_message(&state.config.server.name, "That background is not in the server's list.");
            return;
        }
    }
    {
        let mut area = state.areas[session.area_idx].write().await;
        area.bg = bg.clone();
    }
    state.broadcast_to_area(session.area_idx, "BN", &[&bg]).await;
}

async fn cmd_status(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let is_cm = {
        let area = state.areas[session.area_idx].read().await;
        area.has_cm(session.uid.unwrap_or(0))
    };
    if !is_cm && !perms::has(session.permissions, perms::MODIFY_AREA) {
        session.server_message(&state.config.server.name, "You must be a CM to change the status.");
        return;
    }
    let status_str = args.get(0).map(|s| s.to_uppercase()).unwrap_or_default();
    let status = match status_str.as_str() {
        "IDLE" => Status::Idle,
        "LOOKING-FOR-PLAYERS" | "LFP" => Status::LookingForPlayers,
        "CASING" => Status::Casing,
        "RECESS" => Status::Recess,
        "RP" => Status::Rp,
        "GAMING" => Status::Gaming,
        _ => {
            session.server_message(&state.config.server.name, "Valid statuses: IDLE, LOOKING-FOR-PLAYERS, CASING, RECESS, RP, GAMING");
            return;
        }
    };
    {
        let mut area = state.areas[session.area_idx].write().await;
        area.status = status;
    }
    state.send_status_arup().await;
}

async fn cmd_lock(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let is_cm = {
        let area = state.areas[session.area_idx].read().await;
        area.has_cm(session.uid.unwrap_or(0))
    };
    if !is_cm && !perms::has(session.permissions, perms::MODIFY_AREA) {
        session.server_message(&state.config.server.name, "You must be a CM to lock the area.");
        return;
    }
    let spectatable = args.get(0).map(|s| s == "-s").unwrap_or(false);
    let lock_state = if spectatable { LockState::Spectatable } else { LockState::Locked };
    {
        let mut area = state.areas[session.area_idx].write().await;
        area.lock = lock_state;
    }
    state.send_lock_arup().await;
    session.server_message(&state.config.server.name, "Area locked.");
}

async fn cmd_unlock(session: &mut ClientSession, state: &Arc<ServerState>) {
    let is_cm = {
        let area = state.areas[session.area_idx].read().await;
        area.has_cm(session.uid.unwrap_or(0))
    };
    if !is_cm && !perms::has(session.permissions, perms::MODIFY_AREA) {
        session.server_message(&state.config.server.name, "You must be a CM to unlock the area.");
        return;
    }
    {
        let mut area = state.areas[session.area_idx].write().await;
        area.lock = LockState::Free;
        area.invited.clear();
    }
    state.send_lock_arup().await;
    session.server_message(&state.config.server.name, "Area unlocked.");
}

async fn cmd_play(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let is_cm = {
        let area = state.areas[session.area_idx].read().await;
        area.has_cm(session.uid.unwrap_or(0))
    };
    if !is_cm && !perms::has(session.permissions, perms::CM) {
        session.server_message(&state.config.server.name, "You must be a CM to play music.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /play <song name>");
        return;
    }
    let song = args.join(" ");
    let char_id_str = session.char_id.map(|id| id.to_string()).unwrap_or_else(|| "-1".to_string());
    state.broadcast_to_area(session.area_idx, "MC", &[&song, &char_id_str, &session.ooc_name, "1", "0", "0"]).await;
}

fn cmd_narrator(session: &mut ClientSession, state: &Arc<ServerState>) {
    session.narrator = !session.narrator;
    if session.narrator {
        session.server_message(&state.config.server.name, "Narrator mode enabled.");
    } else {
        session.server_message(&state.config.server.name, "Narrator mode disabled.");
    }
}

async fn cmd_login(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if args.len() < 2 {
        session.server_message(&state.config.server.name, "Usage: /login <username> <password>");
        return;
    }
    let username = args[0].clone();
    let password = args[1..].join(" ");

    // Run Argon2 verification in blocking thread
    let accounts = &state.accounts;
    match accounts.authenticate(&username, &password) {
        Ok(Some(perms)) => {
            session.authenticated = true;
            session.permissions = perms;
            session.mod_name = Some(username.clone());
            session.send_packet("AUTH", &["1"]);
            session.server_message(&state.config.server.name, &format!("Logged in as {}.", username));
            // Update client handle
            if let Some(uid) = session.uid {
                let mut clients = state.clients.lock().await;
                if let Some(handle) = clients.get_mut(&uid) {
                    let handle = Arc::make_mut(handle);
                    handle.authenticated = true;
                }
            }
        }
        Ok(None) => {
            session.send_packet("AUTH", &["-1"]);
            session.server_message(&state.config.server.name, "Invalid credentials.");
        }
        Err(e) => {
            tracing::error!("Auth error: {}", e);
            session.server_message(&state.config.server.name, "Authentication error.");
        }
    }
}

fn cmd_logout(session: &mut ClientSession, state: &Arc<ServerState>) {
    session.authenticated = false;
    session.permissions = 0;
    session.mod_name = None;
    session.send_packet("AUTH", &["-1"]);
    session.server_message(&state.config.server.name, "Logged out.");
}

async fn cmd_mod(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::MOD_SPEAK) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /mod <message>");
        return;
    }
    let msg = args.join(" ");
    let mod_name = session.mod_name.as_deref().unwrap_or("Moderator");
    let encoded_name = format!("[MOD] {}", mod_name);
    state.broadcast("CT", &[&encoded_name, &msg, "1"]).await;
}

async fn cmd_kick(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::KICK) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /kick <uid> [reason]");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => {
            session.server_message(&state.config.server.name, "Invalid UID.");
            return;
        }
    };
    let reason = if args.len() > 1 { args[1..].join(" ") } else { "Kicked by moderator.".into() };
    let clients = state.clients.lock().await;
    if let Some(handle) = clients.get(&target_uid) {
        handle.send(&format!("BD#{}#%", reason));
        // The client's read loop will detect the connection closed and clean up.
    } else {
        drop(clients);
        session.server_message(&state.config.server.name, "Client not found.");
        return;
    }
    drop(clients);
    session.server_message(&state.config.server.name, &format!("Kicked UID {}.", target_uid));
}

async fn cmd_mute(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::MUTE) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /mute <uid> [ic|ooc|all|music|judge]");
        return;
    }
    // NOTE: Mute affects the target session's mute_state.
    // Since each session runs in its own task, we send a special internal control message.
    // For simplicity, we send a server message to the target notifying them.
    // Full cross-task mute would require an additional control channel.
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => {
            session.server_message(&state.config.server.name, "Invalid UID.");
            return;
        }
    };
    let mute_type = args.get(1).map(|s| s.as_str()).unwrap_or("all");
    let clients = state.clients.lock().await;
    if let Some(handle) = clients.get(&target_uid) {
        let msg = format!("__MUTE_{}__", mute_type);
        handle.send(&msg);
        session.server_message(&state.config.server.name, &format!("Muted UID {} ({}).", target_uid, mute_type));
    } else {
        session.server_message(&state.config.server.name, "Client not found.");
    }
}

async fn cmd_unmute(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::MUTE) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /unmute <uid>");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => {
            session.server_message(&state.config.server.name, "Invalid UID.");
            return;
        }
    };
    let clients = state.clients.lock().await;
    if let Some(handle) = clients.get(&target_uid) {
        handle.send("__UNMUTE__");
        session.server_message(&state.config.server.name, &format!("Unmuted UID {}.", target_uid));
    } else {
        session.server_message(&state.config.server.name, "Client not found.");
    }
}

async fn cmd_warn(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::KICK) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.len() < 2 {
        session.server_message(&state.config.server.name, "Usage: /warn <uid> <reason>");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => {
            session.server_message(&state.config.server.name, "Invalid UID.");
            return;
        }
    };
    let reason = args[1..].join(" ");
    let clients = state.clients.lock().await;
    if let Some(handle) = clients.get(&target_uid) {
        handle.send_packet("CT", &[
            &crate::protocol::packet::ao_encode(&state.config.server.name),
            &crate::protocol::packet::ao_encode(&format!("WARNING: {}", reason)),
            "1",
        ]);
        session.server_message(&state.config.server.name, &format!("Warned UID {}.", target_uid));
    } else {
        session.server_message(&state.config.server.name, "Client not found.");
    }
}

async fn cmd_ban(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::BAN) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.len() < 2 {
        session.server_message(&state.config.server.name, "Usage: /ban <uid> <reason>");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => {
            session.server_message(&state.config.server.name, "Invalid UID.");
            return;
        }
    };
    let reason = args[1..].join(" ");

    let hdid = {
        let clients = state.clients.lock().await;
        clients.get(&target_uid).and_then(|h| h.hdid.clone())
    };

    match hdid {
        None => {
            session.server_message(&state.config.server.name, "Client not found or has no HDID.");
        }
        Some(hdid) => {
            let mod_name = session.mod_name.as_deref().unwrap_or("unknown");
            match state.bans.add(&hdid, None, &reason, mod_name) {
                Ok(ban_id) => {
                    // Disconnect the target
                    let clients = state.clients.lock().await;
                    if let Some(handle) = clients.get(&target_uid) {
                        handle.send(&format!("BD#{}#%", reason));
                    }
                    drop(clients);
                    session.server_message(&state.config.server.name, &format!("Banned UID {} (ban ID: {}).", target_uid, ban_id));
                }
                Err(e) => {
                    session.server_message(&state.config.server.name, &format!("Error adding ban: {}", e));
                }
            }
        }
    }
}

async fn cmd_unban(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::BAN) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /unban <ban_id>");
        return;
    }
    let ban_id: u64 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => {
            session.server_message(&state.config.server.name, "Invalid ban ID.");
            return;
        }
    };
    match state.bans.nullify(ban_id) {
        Ok(true) => session.server_message(&state.config.server.name, &format!("Ban {} nullified.", ban_id)),
        Ok(false) => session.server_message(&state.config.server.name, "Ban not found."),
        Err(e) => session.server_message(&state.config.server.name, &format!("Error: {}", e)),
    }
}

async fn cmd_baninfo(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::BAN_INFO) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /baninfo <hashed_hdid>");
        return;
    }
    match state.bans.get_by_hdid(&args[0]) {
        Ok(records) => {
            if records.is_empty() {
                session.server_message(&state.config.server.name, "No bans found.");
            } else {
                for r in &records {
                    let status = if r.is_active() { "ACTIVE" } else { "EXPIRED" };
                    session.server_message(
                        &state.config.server.name,
                        &format!("[{}] ID:{} Until:{} Reason:{} By:{}", status, r.id, r.duration_display(), r.reason, r.moderator),
                    );
                }
            }
        }
        Err(e) => session.server_message(&state.config.server.name, &format!("Error: {}", e)),
    }
}

async fn cmd_announce(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::MOD_SPEAK) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /announce <message>");
        return;
    }
    let msg = args.join(" ");
    state.broadcast("CT", &[
        &crate::protocol::packet::ao_encode(&state.config.server.name),
        &crate::protocol::packet::ao_encode(&format!("[ANNOUNCEMENT] {}", msg)),
        "1",
    ]).await;
}

async fn cmd_modchat(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::MOD_CHAT) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /modchat <message>");
        return;
    }
    let msg = args.join(" ");
    let mod_name = session.mod_name.as_deref().unwrap_or("unknown");
    let clients = state.clients.lock().await;
    for handle in clients.values() {
        if handle.authenticated {
            handle.send_packet("CT", &[
                &format!("[MODCHAT] {}", mod_name),
                &msg,
                "1",
            ]);
        }
    }
}

fn cmd_motd(session: &mut ClientSession, state: &Arc<ServerState>) {
    if state.config.server.motd.is_empty() {
        session.server_message(&state.config.server.name, "No MOTD set.");
    } else {
        session.server_message(&state.config.server.name, &state.config.server.motd);
    }
}

async fn cmd_pair(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let sname = state.config.server.name.clone();
    if session.char_id.is_none() {
        session.server_message(&sname, "You must have a character selected to pair.");
        return;
    }
    if args.is_empty() {
        session.server_message(&sname, "Usage: /pair <uid>");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => { session.server_message(&sname, "Invalid UID."); return; }
    };
    let my_uid = session.uid.unwrap_or(u32::MAX);
    if target_uid == my_uid {
        session.server_message(&sname, "You cannot pair with yourself.");
        return;
    }
    let my_char_id = session.char_id.unwrap();

    // Read target info and check validity
    let (target_char_id, target_char_name, is_mutual, target_tx) = {
        let clients = state.clients.lock().await;
        let target = match clients.get(&target_uid) {
            Some(h) => h,
            None => { session.server_message(&sname, "Player not found."); return; }
        };
        if target.area_idx != session.area_idx {
            session.server_message(&sname, "That player is not in your area.");
            return;
        }
        let target_char_id = match target.char_id {
            Some(id) => id,
            None => { session.server_message(&sname, "That player has no character selected."); return; }
        };
        let target_char_name = state.characters.get(target_char_id).cloned().unwrap_or_default();
        let is_mutual = target.pair_wanted_id == Some(my_char_id);
        let target_tx = target.tx.clone();
        (target_char_id, target_char_name, is_mutual, target_tx)
    };

    // Update session pair state
    session.pair_info.wanted_id = Some(target_char_id);
    if is_mutual {
        session.force_pair_uid = Some(target_uid);
    }

    // Update our ClientHandle and, if mutual, the partner's too
    {
        let mut clients = state.clients.lock().await;
        if let Some(h) = clients.get_mut(&my_uid) {
            let h = Arc::make_mut(h);
            h.pair_wanted_id = Some(target_char_id);
            h.force_pair_uid = if is_mutual { Some(target_uid) } else { None };
        }
        if is_mutual {
            if let Some(h) = clients.get_mut(&target_uid) {
                let h = Arc::make_mut(h);
                h.force_pair_uid = Some(my_uid);
                h.pair_wanted_id = Some(my_char_id);
            }
        }
    }

    let my_char_name = session.char_id
        .and_then(|id| state.characters.get(id))
        .map(|s| s.as_str())
        .unwrap_or("Unknown");

    if is_mutual {
        session.server_message(&sname, &format!("You are now paired with {}.", target_char_name));
        let _ = target_tx.send(format!(
            "CT#{}#{}#1#%",
            ao_encode(&sname),
            ao_encode(&format!("{} is now paired with you.", my_char_name)),
        ));
    } else {
        session.server_message(&sname, &format!(
            "Pair request sent to {}. They must use /pair {} to confirm.",
            target_char_name, my_uid
        ));
        let _ = target_tx.send(format!(
            "CT#{}#{}#1#%",
            ao_encode(&sname),
            ao_encode(&format!("{} wants to pair with you. Use /pair {} to confirm.", my_char_name, my_uid)),
        ));
    }
}

async fn cmd_unpair(session: &mut ClientSession, state: &Arc<ServerState>) {
    let sname = state.config.server.name.clone();
    let my_uid = session.uid.unwrap_or(u32::MAX);
    let my_char_id = session.char_id.unwrap_or(usize::MAX);

    if session.pair_info.wanted_id.is_none() && session.force_pair_uid.is_none() {
        session.server_message(&sname, "You are not paired with anyone.");
        return;
    }

    let my_char_name = session.char_id
        .and_then(|id| state.characters.get(id))
        .map(|s| s.as_str())
        .unwrap_or("Unknown")
        .to_string();

    // If force-paired, clear the partner's side and notify them
    if let Some(force_uid) = session.force_pair_uid {
        let partner_tx = {
            let mut clients = state.clients.lock().await;
            let tx = clients.get(&force_uid).map(|h| h.tx.clone());
            if let Some(h) = clients.get_mut(&force_uid) {
                let h = Arc::make_mut(h);
                h.force_pair_uid = None;
                h.pair_wanted_id = None;
            }
            tx
        };
        if let Some(tx) = partner_tx {
            let _ = tx.send(format!(
                "CT#{}#{}#1#%",
                ao_encode(&sname),
                ao_encode(&format!("{} has ended the pair.", my_char_name)),
            ));
        }
        session.force_pair_uid = None;
    }

    // Notify anyone with a pending (non-force) pair request on us
    {
        let clients = state.clients.lock().await;
        for handle in clients.values() {
            if handle.uid != my_uid && handle.pair_wanted_id == Some(my_char_id) {
                let _ = handle.tx.send(format!(
                    "CT#{}#{}#1#%",
                    ao_encode(&sname),
                    ao_encode("Your pair partner has unpaired."),
                ));
            }
        }
    }

    // Clear our own pair state
    session.pair_info.wanted_id = None;
    {
        let mut clients = state.clients.lock().await;
        if let Some(h) = clients.get_mut(&my_uid) {
            let h = Arc::make_mut(h);
            h.pair_wanted_id = None;
            h.force_pair_uid = None;
        }
    }

    session.server_message(&sname, "You have unpaired.");
}

async fn cmd_clear(session: &mut ClientSession, state: &Arc<ServerState>) {
    let is_cm = {
        let area = state.areas[session.area_idx].read().await;
        area.has_cm(session.uid.unwrap_or(0))
    };
    if !is_cm && !perms::has(session.permissions, perms::MODIFY_AREA) {
        session.server_message(&state.config.server.name, "You must be a CM to clear the chat.");
        return;
    }
    // Send a large CT message to simulate clearing (AO2 doesn't have a dedicated clear packet)
    let spacer = "\n".repeat(50);
    state.broadcast_to_area(session.area_idx, "CT", &[
        &crate::protocol::packet::ao_encode(&state.config.server.name),
        &spacer,
        "1",
    ]).await;
}
