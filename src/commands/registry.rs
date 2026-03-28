use std::sync::Arc;

use chrono::Utc;

use crate::{
    auth::accounts::perms,
    client::ClientSession,
    game::areas::{LockState, Status},
    game::characters::{build_sm_packet, load_lines},
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
        "shadowmute" => cmd_shadowmute(session, state, args).await,
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
        "watchlist" => cmd_watchlist(session, state, args).await,
        "ipban" => cmd_ipban(session, state, args).await,
        "unipban" => cmd_unipban(session, state, args).await,
        "ignore" => cmd_ignore(session, state, args).await,
        "unignore" => cmd_unignore(session, state, args).await,
        "ignorelist" => cmd_ignorelist(session, state).await,
        "pm" => cmd_pm(session, state, args).await,
        "r" => cmd_r(session, state, args).await,
        "reload" => cmd_reload(session, state).await,
        "logoutall" => cmd_logoutall(session, state).await,
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
/pm <uid> <msg>  — private message  |  /r <msg>  — reply to last PM
/ignore <uid>  /unignore <uid>  /ignorelist
/motd /clear
[MOD] /kick <uid> /mute <uid> [ic|ooc|all] /unmute <uid> /shadowmute <uid>
[MOD] /warn <uid> <reason>
[MOD] /ban <uid> <reason> /unban <ban_id> /baninfo <hdid_hash> /announce <msg> /modchat <msg>
[MOD] /ipban <uid> [duration] <reason>  /unipban <ipid>
[MOD] /watchlist add <hdid> [note] | /watchlist remove <hdid> | /watchlist list
[ADMIN] /reload  — hot-reload characters/music/backgrounds
[ADMIN] /logoutall  — force-logout all authenticated sessions";
    session.server_message(&state.config.server.name, msg);
}

fn cmd_about(session: &mut ClientSession, state: &Arc<ServerState>) {
    session.server_message(&state.config.server.name, &format!("NyahAO v0.1.0 - Privacy-first AO2 server"));
}

async fn cmd_who(session: &mut ClientSession, state: &Arc<ServerState>) {
    let characters = {
        let rdata = state.reloadable.read().await;
        rdata.characters.clone()
    };
    let clients = state.clients.lock().await;
    let count = clients.len();
    let list: Vec<String> = clients.values().map(|h| {
        let char_name = h.char_id
            .and_then(|id| characters.get(id))
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
    // Name-based lookup (or numeric index)
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

    // Check per-area player cap before doing anything.
    {
        let new_area = state.areas[new_idx].read().await;
        if let Some(max) = new_area.max_players {
            if new_area.players >= max && !perms::has(session.permissions, perms::BYPASS_LOCK) {
                session.server_message(&state.config.server.name, "That area is at capacity.");
                return;
            }
        }
    }

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

        // Auto-CM for area owner
        if let Some(owner) = &new_area.owner.clone() {
            if let Some(mod_name) = &session.mod_name {
                if mod_name == owner {
                    new_area.add_cm(uid);
                }
            }
        }

        // Send area join info
        let taken = new_area.taken_strings();
        let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
        let bg = new_area.bg.clone();
        session.send_packet("CharsCheck", &taken_refs);
        session.send_packet("HP", &["1", &new_area.def_hp.to_string()]);
        session.send_packet("HP", &["2", &new_area.pro_hp.to_string()]);
        session.send_packet("BN", &[&bg]);

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
        let (lock_bg, force_bglist) = {
            let area = state.areas[session.area_idx].read().await;
            (area.lock_bg, area.force_bglist)
        };
        if lock_bg && !perms::has(session.permissions, perms::MODIFY_AREA) {
            session.server_message(&state.config.server.name, "The background is locked in this area.");
            return;
        }
        if force_bglist {
            let rdata = state.reloadable.read().await;
            if !rdata.backgrounds.contains(&bg) {
                session.server_message(&state.config.server.name, "That background is not in the server's list.");
                return;
            }
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
    // Acquire clients lock to read target info, then drop before awaiting reloadable.
    let (target_char_id, is_mutual, target_tx) = {
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
        let is_mutual = target.pair_wanted_id == Some(my_char_id);
        let target_tx = target.tx.clone();
        (target_char_id, is_mutual, target_tx)
    };
    // Clients lock dropped; now safe to await reloadable.
    let target_char_name = {
        let rdata = state.reloadable.read().await;
        rdata.characters.get(target_char_id).cloned().unwrap_or_default()
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

    let my_char_name = {
        let rdata = state.reloadable.read().await;
        session.char_id
            .and_then(|id| rdata.characters.get(id).cloned())
            .unwrap_or_else(|| "Unknown".to_string())
    };

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

    let my_char_name = {
        let rdata = state.reloadable.read().await;
        session.char_id
            .and_then(|id| rdata.characters.get(id).cloned())
            .unwrap_or_else(|| "Unknown".to_string())
    };

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

async fn cmd_watchlist(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    use crate::auth::accounts::perms;
    if !perms::has(session.permissions, perms::WATCHLIST) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }

    let sname = state.config.server.name.clone();
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");

    match sub {
        "add" => {
            if args.len() < 2 {
                session.server_message(&sname, "Usage: /watchlist add <hdid_hash> [note]");
                return;
            }
            let hdid = &args[1];
            let note = args[2..].join(" ");
            let mod_name = session.mod_name.as_deref().unwrap_or("unknown");
            match state.watchlist.add(hdid, mod_name, &note) {
                Ok(()) => session.server_message(&sname, &format!("Added {}... to watchlist.", &hdid[..hdid.len().min(16)])),
                Err(e) => session.server_message(&sname, &format!("Error: {}", e)),
            }
        }
        "remove" | "rm" => {
            if args.len() < 2 {
                session.server_message(&sname, "Usage: /watchlist remove <hdid_hash>");
                return;
            }
            let hdid = &args[1];
            match state.watchlist.remove(hdid) {
                Ok(true) => session.server_message(&sname, &format!("Removed {}... from watchlist.", &hdid[..hdid.len().min(16)])),
                Ok(false) => session.server_message(&sname, "HDID not found on watchlist."),
                Err(e) => session.server_message(&sname, &format!("Error: {}", e)),
            }
        }
        "list" => {
            match state.watchlist.list() {
                Err(e) => session.server_message(&sname, &format!("Error: {}", e)),
                Ok(entries) if entries.is_empty() => {
                    session.server_message(&sname, "Watchlist is empty.");
                }
                Ok(entries) => {
                    let lines: Vec<String> = entries.iter().map(|e| {
                        let short = &e.hdid[..e.hdid.len().min(16)];
                        if e.note.is_empty() {
                            format!("{}... (added by {})", short, e.added_by)
                        } else {
                            format!("{}... (added by {}) — {}", short, e.added_by, e.note)
                        }
                    }).collect();
                    session.server_message(&sname, &format!("Watchlist ({}):\n{}", entries.len(), lines.join("\n")));
                }
            }
        }
        _ => {
            session.server_message(&sname, "Usage: /watchlist add <hdid> [note] | /watchlist remove <hdid> | /watchlist list");
        }
    }
}

/// /pm <uid> <message> — send a private OOC message to another player.
async fn cmd_pm(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if args.len() < 2 {
        session.server_message(&state.config.server.name, "Usage: /pm <uid> <message>");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => { session.server_message(&state.config.server.name, "Invalid UID."); return; }
    };
    let my_uid = match session.uid {
        Some(uid) => uid,
        None => return,
    };
    if target_uid == my_uid {
        session.server_message(&state.config.server.name, "You cannot PM yourself.");
        return;
    }
    let message = args[1..].join(" ");
    if message.is_empty() { return; }

    let target_tx = {
        let clients = state.clients.lock().await;
        match clients.get(&target_uid) {
            Some(h) => h.tx.clone(),
            None => { session.server_message(&state.config.server.name, "Player not found."); return; }
        }
    };

    let sender_name = if session.ooc_name.is_empty() {
        format!("UID {}", my_uid)
    } else {
        session.ooc_name.clone()
    };

    // Send to target
    let pm_header = ao_encode(&format!("[PM from {}]", sender_name));
    let pm_msg = ao_encode(&message);
    let _ = target_tx.send(format!("CT#{}#{}#1#%", pm_header, pm_msg));

    // Confirm to sender
    let confirm_header = ao_encode(&format!("[PM to UID {}]", target_uid));
    session.send_packet("CT", &[&confirm_header, &pm_msg, "1"]);

    // Tell the target session to update last_pm_uid (via internal message).
    let _ = target_tx.send(format!("__PM_FROM_{}__", my_uid));

    session.last_pm_uid = Some(target_uid);
}

/// /r <message> — reply to the last PM received.
async fn cmd_r(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    match session.last_pm_uid {
        None => { session.server_message(&state.config.server.name, "No one to reply to."); }
        Some(uid) => {
            let mut new_args = vec![uid.to_string()];
            new_args.extend(args);
            cmd_pm(session, state, new_args).await;
        }
    }
}

/// /shadowmute <uid> — stealth-mute a player (MOD only).
async fn cmd_shadowmute(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::MUTE) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /shadowmute <uid>");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => { session.server_message(&state.config.server.name, "Invalid UID."); return; }
    };
    let clients = state.clients.lock().await;
    if let Some(handle) = clients.get(&target_uid) {
        handle.send("__SHADOWMUTE__");
        session.server_message(&state.config.server.name, &format!("Shadowmuted UID {}.", target_uid));
    } else {
        session.server_message(&state.config.server.name, "Client not found.");
    }
}

/// /ipban <uid> [duration] <reason> — ban a player by their current IPID (MOD only).
/// Duration format: 1h, 6h, 12h, 1d, 7d — omit for a permanent ban (until daily rotation).
async fn cmd_ipban(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::KICK) {
        session.server_message(&state.config.server.name, "No permission.");
        return;
    }
    if args.is_empty() {
        session.server_message(&state.config.server.name, "Usage: /ipban <uid> [duration] <reason>");
        return;
    }
    let sname = state.config.server.name.clone();
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => { session.server_message(&sname, "Invalid UID."); return; }
    };

    // Get target's IPID and name from shared handle
    let (target_ipid, target_char) = {
        let clients = state.clients.lock().await;
        match clients.get(&target_uid) {
            Some(h) => {
                let char_name = h.char_id
                    .and_then(|id| {
                        // We can't await here so just use the raw char_id as string fallback
                        Some(format!("UID {}", h.uid))
                    })
                    .unwrap_or_else(|| format!("UID {}", h.uid));
                (h.ipid.clone(), char_name)
            }
            None => { session.server_message(&sname, "Player not found."); return; }
        }
    };

    // Parse optional duration and reason
    let (expires_at, reason) = if args.len() >= 2 {
        let maybe_dur = &args[1];
        let dur_secs: Option<i64> = if maybe_dur.ends_with('h') {
            maybe_dur[..maybe_dur.len()-1].parse::<i64>().ok().map(|h| h * 3600)
        } else if maybe_dur.ends_with('d') {
            maybe_dur[..maybe_dur.len()-1].parse::<i64>().ok().map(|d| d * 86400)
        } else {
            None
        };
        if let Some(secs) = dur_secs {
            let exp = Utc::now().timestamp() + secs;
            let reason = args[2..].join(" ");
            if reason.is_empty() {
                session.server_message(&sname, "Please provide a reason after the duration.");
                return;
            }
            (Some(exp), reason)
        } else {
            (None, args[1..].join(" "))
        }
    } else {
        session.server_message(&sname, "Usage: /ipban <uid> [duration] <reason>");
        return;
    };

    if reason.is_empty() {
        session.server_message(&sname, "Please provide a ban reason.");
        return;
    }

    let moderator = session.mod_name.clone().unwrap_or_else(|| "unknown".into());
    match state.ipid_bans.add(&target_ipid, expires_at, &reason, &moderator) {
        Ok(()) => {
            session.server_message(&sname, &format!(
                "IPID-banned {} (IPID: {}…). Reason: {}",
                target_char,
                &target_ipid[..target_ipid.len().min(8)],
                reason
            ));
            // Kick the target
            let clients = state.clients.lock().await;
            if let Some(h) = clients.get(&target_uid) {
                h.send_packet("BD", &[&format!("{}\n(IPID ban)", reason)]);
            }
        }
        Err(e) => session.server_message(&sname, &format!("DB error: {}", e)),
    }
}

/// /unipban <ipid> — remove an IPID ban (MOD only).
async fn cmd_unipban(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    if !perms::has(session.permissions, perms::BAN) {
        session.server_message(&state.config.server.name, "No permission. BAN required.");
        return;
    }
    let sname = state.config.server.name.clone();
    if args.is_empty() {
        session.server_message(&sname, "Usage: /unipban <ipid>");
        return;
    }
    let ipid = &args[0];
    match state.ipid_bans.remove(ipid) {
        Ok(true) => session.server_message(&sname, &format!("Removed IPID ban for {}.", ipid)),
        Ok(false) => session.server_message(&sname, "No IPID ban found for that value."),
        Err(e) => session.server_message(&sname, &format!("DB error: {}", e)),
    }
}

/// /ignore <uid> — hide IC and OOC messages from a player (session only, resets on disconnect).
async fn cmd_ignore(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let sname = state.config.server.name.clone();
    if args.is_empty() {
        session.server_message(&sname, "Usage: /ignore <uid>");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => { session.server_message(&sname, "Invalid UID."); return; }
    };
    let my_uid = match session.uid {
        Some(u) => u,
        None => return,
    };
    if target_uid == my_uid {
        session.server_message(&sname, "You cannot ignore yourself.");
        return;
    }
    // Check they exist and get display name
    let exists = {
        let clients = state.clients.lock().await;
        clients.contains_key(&target_uid)
    };
    if !exists {
        session.server_message(&sname, "Player not found.");
        return;
    }
    // Update our ClientHandle
    {
        let mut clients = state.clients.lock().await;
        if let Some(h) = clients.get_mut(&my_uid) {
            Arc::make_mut(h).ignored_uids.insert(target_uid);
        }
    }
    session.server_message(&sname, &format!("You are now ignoring UID {}.", target_uid));
}

/// /unignore <uid> — stop ignoring a player.
async fn cmd_unignore(session: &mut ClientSession, state: &Arc<ServerState>, args: Vec<String>) {
    let sname = state.config.server.name.clone();
    if args.is_empty() {
        session.server_message(&sname, "Usage: /unignore <uid>");
        return;
    }
    let target_uid: u32 = match args[0].parse() {
        Ok(n) => n,
        Err(_) => { session.server_message(&sname, "Invalid UID."); return; }
    };
    let my_uid = match session.uid {
        Some(u) => u,
        None => return,
    };
    {
        let mut clients = state.clients.lock().await;
        if let Some(h) = clients.get_mut(&my_uid) {
            Arc::make_mut(h).ignored_uids.remove(&target_uid);
        }
    }
    session.server_message(&sname, &format!("You are no longer ignoring UID {}.", target_uid));
}

/// /ignorelist — show all UIDs you are currently ignoring.
async fn cmd_ignorelist(session: &mut ClientSession, state: &Arc<ServerState>) {
    let sname = state.config.server.name.clone();
    let my_uid = match session.uid {
        Some(u) => u,
        None => return,
    };
    let ignored: Vec<u32> = {
        let clients = state.clients.lock().await;
        clients.get(&my_uid)
            .map(|h| h.ignored_uids.iter().copied().collect())
            .unwrap_or_default()
    };
    if ignored.is_empty() {
        session.server_message(&sname, "You are not ignoring anyone.");
    } else {
        let list: Vec<String> = ignored.iter().map(|u| u.to_string()).collect();
        session.server_message(&sname, &format!("Ignored UIDs: {}", list.join(", ")));
    }
}

/// /reload — hot-reload characters, music, and backgrounds (ADMIN only).
async fn cmd_reload(session: &mut ClientSession, state: &Arc<ServerState>) {
    if !perms::has(session.permissions, perms::ADMIN) {
        session.server_message(&state.config.server.name, "No permission. Admin required.");
        return;
    }

    let characters = match load_lines(std::path::Path::new("data/characters.txt")) {
        Ok(c) => c,
        Err(e) => { session.server_message(&state.config.server.name, &format!("Failed to load characters.txt: {}", e)); return; }
    };
    let music = match load_lines(std::path::Path::new("data/music.txt")) {
        Ok(m) => m,
        Err(e) => { session.server_message(&state.config.server.name, &format!("Failed to load music.txt: {}", e)); return; }
    };
    let backgrounds = match load_lines(std::path::Path::new("data/backgrounds.txt")) {
        Ok(b) => b,
        Err(e) => { session.server_message(&state.config.server.name, &format!("Failed to load backgrounds.txt: {}", e)); return; }
    };

    // Build new SM packet using current area names.
    let area_names: Vec<String> = {
        let mut names = Vec::new();
        for area_arc in &state.areas {
            let area = area_arc.read().await;
            names.push(area.name.clone());
        }
        names
    };
    let area_name_refs: Vec<&str> = area_names.iter().map(|s| s.as_str()).collect();
    let sm_packet = build_sm_packet(&area_name_refs, &music);

    let censor_words = crate::game::characters::load_censor_words(std::path::Path::new("data/censor.txt"));
    let counts = format!(
        "{} chars, {} music, {} backgrounds, {} censor words",
        characters.len(), music.len(), backgrounds.len(), censor_words.len()
    );
    {
        let mut data = state.reloadable.write().await;
        data.characters = characters;
        data.music = music;
        data.backgrounds = backgrounds;
        data.sm_packet = sm_packet;
        data.censor_words = censor_words;
    }

    session.server_message(&state.config.server.name, &format!("Reloaded: {}", counts));
    tracing::info!("Game data reloaded by {}: {}", session.mod_name.as_deref().unwrap_or("unknown"), counts);
}

/// /logoutall — force-logout all authenticated sessions except caller (ADMIN only).
async fn cmd_logoutall(session: &mut ClientSession, state: &Arc<ServerState>) {
    if !perms::has(session.permissions, perms::ADMIN) {
        session.server_message(&state.config.server.name, "No permission. Admin required.");
        return;
    }
    let my_uid = session.uid.unwrap_or(u32::MAX);
    let clients = state.clients.lock().await;
    let mut count = 0usize;
    for handle in clients.values() {
        if handle.authenticated && handle.uid != my_uid {
            handle.send("__LOGOUT__");
            count += 1;
        }
    }
    drop(clients);
    session.server_message(&state.config.server.name, &format!("Logged out {} authenticated session(s).", count));
}
