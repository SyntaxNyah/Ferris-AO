/// All AO2 packet handlers.
/// Each handler takes: &mut ClientSession, &Packet, &Arc<ServerState>
/// and runs inside the client's async task.
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::{
    auth::accounts::perms,
    client::{ClientSession, MuteState, PairInfo},
    commands::dispatch_command,
    game::areas::LockState,
    protocol::packet::{ao_decode, ao_encode, Packet},
    server::{ClientHandle, ServerState, VERSION},
};

/// The feature flags advertised to AO2 clients.
const FEATURES: &[&str] = &[
    "noencryption",
    "yellowtext",
    "prezoom",
    "flipping",
    "customobjections",
    "fastloading",
    "deskmod",
    "evidence",
    "cccc_ic_support",
    "arup",
    "casing_alerts",
    "modcall_reason",
    "looping_sfx",
    "additive",
    "effects",
    "y_offset",
    "expanded_desk_mods",
    "auth_packet",
];

/// Dispatch a parsed packet to the correct handler.
pub async fn dispatch(session: &mut ClientSession, state: &Arc<ServerState>, pkt: Packet) {
    // Handle internal control messages from mute/unmute commands
    if pkt.header.starts_with("__") {
        handle_internal(session, state, &pkt.header).await;
        return;
    }

    // Check minimum args and MustJoin requirement
    let (min_args, must_join) = match pkt.header.as_str() {
        "HI" => (1, false),
        "ID" => (2, false),
        "askchaa" => (0, false),
        "RC" => (0, false),
        "RM" => (0, false),
        "RD" => (0, false),
        "CH" => (0, false),
        "CC" => (3, true),
        "MS" => (15, true),
        "MC" => (2, true),
        "HP" => (2, true),
        "RT" => (1, true),
        "CT" => (2, true),
        "PE" => (3, true),
        "DE" => (1, true),
        "EE" => (4, true),
        "ZZ" => (0, true),
        "SETCASE" => (7, true),
        "CASEA" => (6, true),
        _ => return, // Unknown packet — discard silently
    };

    if pkt.body.len() < min_args {
        return;
    }
    if must_join && session.uid.is_none() {
        return;
    }

    match pkt.header.as_str() {
        "HI" => handle_hi(session, state, &pkt).await,
        "ID" => handle_id(session, state, &pkt).await,
        "askchaa" => handle_askchaa(session, state).await,
        "RC" => handle_rc(session, state).await,
        "RM" => handle_rm(session, state).await,
        "RD" => handle_rd(session, state).await,
        "CH" => handle_ch(session),
        "CC" => handle_cc(session, state, &pkt).await,
        "MS" => handle_ms(session, state, &pkt).await,
        "MC" => handle_mc(session, state, &pkt).await,
        "HP" => handle_hp(session, state, &pkt).await,
        "RT" => handle_rt(session, state, &pkt).await,
        "CT" => handle_ct(session, state, &pkt).await,
        "PE" => handle_pe(session, state, &pkt).await,
        "DE" => handle_de(session, state, &pkt).await,
        "EE" => handle_ee(session, state, &pkt).await,
        "ZZ" => handle_zz(session, state, &pkt).await,
        "SETCASE" => handle_setcase(session, &pkt),
        "CASEA" => handle_casea(session, state, &pkt).await,
        _ => {}
    }
}

/// Handle internal control messages sent between tasks via the TX channel.
async fn handle_internal(session: &mut ClientSession, state: &Arc<ServerState>, header: &str) {
    match header {
        "__UNMUTE__" => {
            session.mute_state = MuteState::None;
            session.mute_until = None;
            session.server_message(&state.config.server.name, "You have been unmuted.");
        }
        "__SHADOWMUTE__" => {
            // Stealth mute — do NOT notify the victim.
            session.mute_state = MuteState::Shadowmute;
        }
        "__LOGOUT__" => {
            // Force-logout: clear auth state, notify client, update handle.
            session.authenticated = false;
            session.permissions = 0;
            session.mod_name = None;
            session.send_packet("AUTH", &["-1"]);
            session.server_message(&state.config.server.name, "You have been remotely logged out.");
            if let Some(uid) = session.uid {
                let mut clients = state.clients.lock().await;
                if let Some(h) = clients.get_mut(&uid) {
                    Arc::make_mut(h).authenticated = false;
                }
            }
        }
        s if s.starts_with("__MUTE_") => {
            let kind = s.strip_prefix("__MUTE_").unwrap_or("all").strip_suffix("__").unwrap_or("all");
            session.mute_state = match kind {
                "ic" => MuteState::Ic,
                "ooc" => MuteState::Ooc,
                "music" => MuteState::Music,
                "judge" => MuteState::Judge,
                _ => MuteState::IcOoc,
            };
            session.server_message(&state.config.server.name, &format!("You have been muted ({}).", kind));
        }
        s if s.starts_with("__PM_FROM_") && s.ends_with("__") => {
            // Update last_pm_uid so the victim can use /r
            if let Some(uid_str) = s.strip_prefix("__PM_FROM_").and_then(|t| t.strip_suffix("__")) {
                if let Ok(uid) = uid_str.parse::<u32>() {
                    session.last_pm_uid = Some(uid);
                }
            }
        }
        _ => {}
    }
}

/// HI#HDID%
async fn handle_hi(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    let raw_hdid = ao_decode(&pkt.body[0]);
    if raw_hdid.trim().is_empty() || session.uid.is_some() || session.hdid.is_some() {
        return;
    }

    // Hash HDID immediately — raw value is dropped after this function
    let hashed_hdid = state.privacy.hash_hdid(&raw_hdid);
    session.hdid = Some(hashed_hdid.clone());

    // Check HDID ban
    match state.bans.is_banned(&hashed_hdid) {
        Ok(Some(ban)) => {
            session.send_packet("BD", &[&format!(
                "{}\nUntil: {}\nID: {}",
                ban.reason,
                ban.duration_display(),
                ban.id
            )]);
            return; // Connection will be closed by the read loop detecting TX closed
        }
        Err(e) => warn!("Ban check error for IPID {}: {}", session.ipid, e),
        Ok(None) => {}
    }

    // Check IPID ban
    match state.ipid_bans.is_banned(&session.ipid) {
        Ok(Some(ban)) => {
            session.send_packet("BD", &[&format!(
                "{}\nUntil: {}\n(IPID ban — resets at midnight UTC)",
                ban.reason,
                ban.duration_display(),
            )]);
            return;
        }
        Err(e) => warn!("IPID ban check error for IPID {}: {}", session.ipid, e),
        Ok(None) => {}
    }

    // Check watchlist — notify all online authenticated mods if this HDID is flagged.
    match state.watchlist.get(&hashed_hdid) {
        Ok(Some(entry)) => {
            let short_hdid = &hashed_hdid[..hashed_hdid.len().min(16)];
            let alert = format!(
                "[WATCHLIST] Watched user connected\nHDID: {}...\nAdded by: {}\nNote: {}",
                short_hdid,
                entry.added_by,
                if entry.note.is_empty() { "(none)" } else { &entry.note },
            );
            let clients = state.clients.lock().await;
            for handle in clients.values() {
                if handle.authenticated {
                    handle.send_packet("CT", &[
                        &crate::protocol::packet::ao_encode(&state.config.server.name),
                        &crate::protocol::packet::ao_encode(&alert),
                        "1",
                    ]);
                }
            }
        }
        Err(e) => warn!("Watchlist check error for IPID {}: {}", session.ipid, e),
        Ok(None) => {}
    }

    session.send_packet("ID", &["0", &state.config.server.name, VERSION]);
}

/// ID#software#version%
async fn handle_id(session: &mut ClientSession, state: &Arc<ServerState>, _pkt: &Packet) {
    if session.uid.is_some() {
        return;
    }
    let player_count = state.player_count().to_string();
    let max_players = state.config.server.max_players.to_string();
    let desc = ao_encode(&state.config.server.description);
    session.send_packet("PN", &[&player_count, &max_players, &desc]);
    session.send_packet("FL", FEATURES);
    if !state.config.server.asset_url.is_empty() {
        session.send_packet("ASS", &[&state.config.server.asset_url]);
    }
}

/// askchaa#%
async fn handle_askchaa(session: &mut ClientSession, state: &Arc<ServerState>) {
    if session.uid.is_some() || session.hdid.is_none() {
        return;
    }
    if state.player_count() >= state.config.server.max_players {
        session.send_packet("BD", &["This server is currently full."]);
        return;
    }
    session.joining = true;
    let (char_count, music_count) = {
        let rdata = state.reloadable.read().await;
        (rdata.characters.len().to_string(), rdata.music.len().to_string())
    };
    let area0 = state.areas[0].read().await;
    let evi_count = area0.evidence.len().to_string();
    drop(area0);
    session.send_packet("SI", &[&char_count, &evi_count, &music_count]);
}

/// RC#%
async fn handle_rc(session: &mut ClientSession, state: &Arc<ServerState>) {
    let characters = {
        let rdata = state.reloadable.read().await;
        rdata.characters.clone()
    };
    let refs: Vec<&str> = characters.iter().map(|s| s.as_str()).collect();
    session.send_packet("SC", &refs);
}

/// RM#%
async fn handle_rm(session: &mut ClientSession, state: &Arc<ServerState>) {
    let sm = {
        let rdata = state.reloadable.read().await;
        rdata.sm_packet.clone()
    };
    session.send_raw(&sm);
}

/// RD#%
async fn handle_rd(session: &mut ClientSession, state: &Arc<ServerState>) {
    if session.uid.is_some() || !session.joining || session.hdid.is_none() {
        return;
    }

    // Check multiclient limit
    if state.config.server.multiclient_limit > 0 {
        let clients = state.clients.lock().await;
        let count = clients.values().filter(|h| h.ipid == session.ipid).count();
        drop(clients);
        if count >= state.config.server.multiclient_limit {
            session.send_packet("BD", &["You have reached the server's multiclient limit."]);
            return;
        }
    }

    let uid = match state.alloc_uid().await {
        Some(uid) => uid,
        None => {
            session.send_packet("BD", &["Server is full."]);
            return;
        }
    };
    session.uid = Some(uid);

    // Increment player count
    state.player_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _ = state.player_watch_tx.send(state.player_count());

    // Join area 0
    {
        let mut area = state.areas[0].write().await;
        area.players += 1;
        let taken = area.taken_strings();
        let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
        let evi = area.evidence.clone();
        let evi_refs: Vec<&str> = evi.iter().map(|s| s.as_str()).collect();
        let bg = area.bg.clone();
        session.send_packet("LE", &evi_refs);
        session.send_packet("CharsCheck", &taken_refs);
        session.send_packet("HP", &["1", &area.def_hp.to_string()]);
        session.send_packet("HP", &["2", &area.pro_hp.to_string()]);
        session.send_packet("BN", &[&bg]);
    }

    // Send DONE
    session.send_packet("DONE", &[]);

    // Send MOTD
    if !state.config.server.motd.is_empty() {
        session.server_message(&state.config.server.name, &state.config.server.motd);
    }

    // Register client handle
    let handle = Arc::new(ClientHandle {
        uid,
        area_idx: 0,
        ipid: session.ipid.clone(),
        hdid: session.hdid.clone(),
        char_id: None,
        authenticated: false,
        tx: session.tx.clone(),
        pair_wanted_id: None,
        force_pair_uid: None,
        pair_info: Default::default(),
        pos: String::new(),
        ignored_uids: std::collections::HashSet::new(),
    });
    state.add_client(handle).await;

    info!("Client (IPID:{} UID:{}) joined", session.ipid, uid);

    // ARUP broadcasts
    state.send_player_arup().await;
    state.send_cm_arup().await;
    state.send_status_arup().await;
    state.send_lock_arup().await;
}

/// CH#%
fn handle_ch(session: &mut ClientSession) {
    session.send_raw("CHECK#%");
}

/// CC#uid#char_id#hdid%
async fn handle_cc(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    let new_id: usize = match pkt.body[1].parse() {
        Ok(n) => n,
        Err(_) => return,
    };
    let char_name = {
        let rdata = state.reloadable.read().await;
        if new_id >= rdata.characters.len() {
            return;
        }
        rdata.characters[new_id].clone()
    };
    let uid = session.uid.unwrap_or(0);
    let old_id = session.char_id;

    let ok = {
        let mut area = state.areas[session.area_idx].write().await;
        area.switch_char(old_id, new_id)
    };

    if ok {
        session.char_id = Some(new_id);
        session.showname = char_name;
        // Update client handle
        {
            let mut clients = state.clients.lock().await;
            if let Some(handle) = clients.get_mut(&uid) {
                let handle = Arc::make_mut(handle);
                handle.char_id = Some(new_id);
            }
        }
        session.send_packet("PV", &["0", "CID", &new_id.to_string()]);
        let taken = {
            let area = state.areas[session.area_idx].read().await;
            area.taken_strings()
        };
        let taken_refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
        state.broadcast_to_area(session.area_idx, "CharsCheck", &taken_refs).await;
    }
}

/// MS#desk_mod#pre_anim#char_name#anim#msg#side#sfx_name#emote_mod#char_id#sfx_delay#
///    objection_mod#evidence#flip#realization#text_color#showname#other_charid#self_offset#immediate#...%
async fn handle_ms(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    debug!("MS recv uid={:?} char_id={:?} fields={}", session.uid, session.char_id, pkt.body.len());
    if !session.rl_ic.try_consume() {
        debug!("MS drop: rate limited");
        return;
    }
    let shadowmuted = session.is_shadowmuted();
    if !session.can_speak_ic() {
        session.server_message(&state.config.server.name, "You are not allowed to speak in this area.");
        debug!("MS drop: can_speak_ic false (char_id={:?} mute={:?})", session.char_id, session.mute_state);
        return;
    }

    // Build 26-element array from client packet (client sends variable length)
    let mut client_args: [&str; 26] = [""; 26];
    for (i, s) in pkt.body.iter().take(26).enumerate() {
        client_args[i] = s;
    }

    // Build the server MS packet (29 fields):
    // Client fields 0-16 unchanged.
    // Server inserts at [17]=OTHER_NAME, [18]=OTHER_EMOTE, [20]=OTHER_OFFSET.
    // Client [17]=SELF_OFFSET → server [19]
    // Client [18]=OTHER_FLIP/IMMEDIATE → server [21] ... wait
    // Per our analysis:
    // Client: [17]=SELF_OFFSET, [18]=IMMEDIATE, [19]=LOOPING_SFX, [20]=SCREENSHAKE
    // Server: [17]=OTHER_NAME(new), [18]=OTHER_EMOTE(new), [19]=SELF_OFFSET,
    //         [20]=OTHER_OFFSET(new), [21]=OTHER_FLIP, [22]=IMMEDIATE, [23]=LOOPING_SFX,
    //         [24]=SCREENSHAKE, [25-27]=FRAME_*, [28]=ADDITIVE
    let mut args: Vec<String> = Vec::with_capacity(29);
    for i in 0..17 {
        args.push(client_args[i].to_string());
    }
    // [17] OTHER_NAME - will be filled in pairing logic
    args.push(String::new());
    // [18] OTHER_EMOTE - will be filled in pairing logic
    args.push(String::new());
    // [19] SELF_OFFSET - was client [17]
    args.push(client_args[17].to_string());
    // [20] OTHER_OFFSET - will be filled by pairing
    args.push(String::new());
    // [21] OTHER_FLIP - will be filled by pairing
    args.push(String::new());
    // [22] IMMEDIATE - was client [18]
    args.push(client_args[18].to_string());
    // [23] LOOPING_SFX - was client [19]
    args.push(client_args[19].to_string());
    // [24] SCREENSHAKE - was client [20]
    args.push(client_args[20].to_string());
    // [25] FRAME_SCREENSHAKE - was client [21]
    args.push(client_args[21].to_string());
    // [26] FRAME_REALIZATION - was client [22]
    args.push(client_args[22].to_string());
    // [27] FRAME_SFX - was client [23]
    args.push(client_args[23].to_string());
    // [28] ADDITIVE - was client [24]
    args.push(client_args[24].to_string());

    // Validate emote_mod
    let emote_mod: i32 = match args[7].parse() {
        Ok(n) => n,
        Err(_) => { debug!("MS drop: emote_mod parse fail {:?}", args[7]); return; }
    };
    let emote_mod = if emote_mod == 4 {
        args[7] = "6".into();
        6i32
    } else {
        emote_mod
    };
    if emote_mod < 0 || emote_mod > 6 {
        debug!("MS drop: emote_mod out of range {}", emote_mod);
        return;
    }

    // Validate objection_mod
    let objection_str = args[10].split('&').next().unwrap_or("0");
    let objection: i32 = match objection_str.parse() {
        Ok(n) => n,
        Err(_) => { debug!("MS drop: objection parse fail {:?}", args[10]); return; }
    };
    if objection < 0 || objection > 4 {
        debug!("MS drop: objection out of range {}", objection);
        return;
    }

    // Validate evidence
    let evi: usize = match args[11].parse() {
        Ok(n) => n,
        Err(_) => { debug!("MS drop: evidence parse fail {:?}", args[11]); return; }
    };
    {
        let area = state.areas[session.area_idx].read().await;
        if evi > area.evidence.len() {
            debug!("MS drop: evidence idx {} > len {}", evi, area.evidence.len());
            return;
        }
    }

    // Validate text_color
    let text_color: i32 = match args[14].parse() {
        Ok(n) => n,
        Err(_) => { debug!("MS drop: text_color parse fail {:?}", args[14]); return; }
    };
    if text_color < 0 || text_color > 11 {
        debug!("MS drop: text_color out of range {}", text_color);
        return;
    }

    // Validate char_id
    let char_id_str = session.char_id.map(|id| id.to_string()).unwrap_or_default();
    if args[8] != char_id_str {
        debug!("MS drop: char_id mismatch pkt={:?} session={:?}", args[8], char_id_str);
        return;
    }

    // Validate message length
    if ao_decode(&args[4]).len() > state.config.server.max_message_len {
        session.server_message(&state.config.server.name, "Your message exceeds the maximum length.");
        return;
    }

    // Duplicate message check
    if args[4] == session.last_msg {
        debug!("MS drop: duplicate message");
        return;
    }

    // Iniswap check
    {
        let allow_iniswap = {
            let area = state.areas[session.area_idx].read().await;
            area.allow_iniswap
        };
        if !allow_iniswap {
            if let Some(char_id) = session.char_id {
                let char_name_owned = {
                    let rdata = state.reloadable.read().await;
                    rdata.characters.get(char_id).cloned().unwrap_or_default()
                };
                if !args[2].eq_ignore_ascii_case(&char_name_owned) {
                    session.server_message(&state.config.server.name, "Iniswapping is not allowed in this area.");
                    return;
                }
            }
        }
    }

    // Showname length
    if args[15].len() > 30 {
        session.server_message(&state.config.server.name, "Your showname is too long.");
        return;
    }

    // Default empty booleans
    if args[12].is_empty() { args[12] = "0".into(); }
    if args[13].is_empty() { args[13] = "0".into(); }
    if args[22].is_empty() { args[22] = "0".into(); }
    if args[23].is_empty() { args[23] = "0".into(); }
    if args[24].is_empty() { args[24] = "0".into(); }
    if args[28].is_empty() { args[28] = "0".into(); }

    // Validate boolean fields
    for idx in [12, 13, 22, 23, 24, 28] {
        let v = args.get(idx).map(|s| s.as_str()).unwrap_or("0");
        if v != "0" && v != "1" {
            debug!("MS drop: boolean field[{}]={:?}", idx, v);
            return;
        }
    }

    // Handle additive (args[28])
    {
        let is_last_speaker = session.char_id == {
            let area = state.areas[session.area_idx].read().await;
            area.last_speaker
        };
        if args.get(28).map(|s| s.as_str()).unwrap_or("") == ""
            || !is_last_speaker
        {
            if let Some(v) = args.get_mut(28) { *v = "0".into(); }
        }
    }

    // No-interrupt logic
    {
        let area = state.areas[session.area_idx].read().await;
        let immediate = args[22].as_str();
        if (area.force_nointerrupt && emote_mod != 0) || immediate == "1" {
            args[22] = "1".into();
            if emote_mod == 1 || emote_mod == 2 {
                args[7] = "0".into();
            } else if emote_mod == 6 {
                args[7] = "5".into();
            }
        }
    }

    // Validate self_offset (field is AO-encoded; "&" separating x and y is encoded as "<and>")
    if !args[19].is_empty() {
        let decoded = ao_decode(&args[19]);
        for off in decoded.split('&') {
            let n: i32 = match off.parse() {
                Ok(v) => v,
                Err(_) => { debug!("MS drop: self_offset parse fail {:?}", args[19]); return; }
            };
            if n < -100 || n > 100 {
                debug!("MS drop: self_offset out of range {}", n);
                return;
            }
        }
    }

    // ── Pairing ──────────────────────────────────────────────────────────────────
    let my_uid = session.uid.unwrap_or(u32::MAX);
    let my_char_id = session.char_id.unwrap_or(usize::MAX);
    // Pre-fetch chars_len before acquiring clients lock to avoid holding both simultaneously.
    let chars_len_for_pairing = {
        let rdata = state.reloadable.read().await;
        rdata.characters.len()
    };
    {
        let mut clients = state.clients.lock().await;

        // Phase 1: Force-pair sync — override args[16] to partner's current char_id.
        if let Some(force_uid) = session.force_pair_uid {
            let partner_info = clients.get(&force_uid).map(|h| (h.char_id, h.pos.clone()));
            match partner_info {
                Some((Some(pid), ppos)) => {
                    args[16] = pid.to_string();
                    session.pair_info.wanted_id = Some(pid);
                    // Keep partner's wanted_id pointed at our current char.
                    if let Some(ph) = clients.get_mut(&force_uid) {
                        Arc::make_mut(ph).pair_wanted_id = session.char_id;
                    }
                    // Sync our position to partner's.
                    if !ppos.is_empty() {
                        args[5] = ppos;
                    }
                }
                _ => {
                    // Partner gone or has no character — drop the force-pair bond.
                    session.force_pair_uid = None;
                    args[16] = "-1".to_string();
                }
            }
        }

        // Phase 2: If client didn't send a pair target but server has a wanted_id, inject it.
        {
            let cur = args[16].split('^').next().unwrap_or("").trim();
            if cur.is_empty() || cur == "-1" {
                if let Some(wanted) = session.pair_info.wanted_id {
                    args[16] = wanted.to_string();
                }
            }
        }

        // Phase 3: Find a matching pair partner in the area.
        let pair_str = args[16].split('^').next().unwrap_or("").trim().to_string();
        let mut found: Option<(String, String, String, String)> = None;

        if !pair_str.is_empty() && pair_str != "-1" {
            if let Ok(pair_id) = pair_str.parse::<usize>() {
                if pair_id < chars_len_for_pairing && session.char_id != Some(pair_id) {
                    session.pair_info.wanted_id = Some(pair_id);
                    let force_uid = session.force_pair_uid;
                    let my_pos = args[5].clone(); // Use position after possible force-sync

                    for handle in clients.values() {
                        if handle.uid == my_uid || handle.area_idx != session.area_idx {
                            continue;
                        }
                        let is_force = force_uid
                            .map(|f| f == handle.uid && handle.force_pair_uid == Some(my_uid))
                            .unwrap_or(false);
                        // With a force-pair bond, only match that specific partner.
                        if force_uid.is_some() && !is_force {
                            continue;
                        }
                        // Skip candidates force-bonded to someone else.
                        if handle.force_pair_uid.is_some() && handle.force_pair_uid != Some(my_uid) {
                            continue;
                        }
                        if handle.char_id == Some(pair_id)
                            && handle.pair_wanted_id == Some(my_char_id)
                            && (is_force || handle.pos == my_pos)
                        {
                            found = Some((
                                handle.pair_info.char_name.clone(),
                                handle.pair_info.emote.clone(),
                                handle.pair_info.offset.clone(),
                                handle.pair_info.flip.clone(),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        if let Some((pname, pemote, poffset, pflip)) = found {
            args[17] = pname;
            args[18] = pemote;
            args[20] = poffset;
            args[21] = pflip;
        } else {
            args[16] = "-1".to_string();
            args[17].clear();
            args[18].clear();
        }
    }

    // Update session state
    session.pair_info = PairInfo {
        char_name: args[2].clone(),
        emote: args[3].clone(),
        flip: args[12].clone(),
        offset: args[19].clone(),
        wanted_id: session.pair_info.wanted_id,
    };
    session.last_msg = args[4].clone();
    let char_name = {
        let rdata = state.reloadable.read().await;
        session.char_id
            .and_then(|id| rdata.characters.get(id).cloned())
            .unwrap_or_else(|| "Unknown".to_string())
    };
    session.showname = if args[15].trim().is_empty() {
        char_name.clone()
    } else {
        args[15].clone()
    };
    session.pos = args[5].clone();

    // Sync updated pair state and position to the shared ClientHandle.
    {
        let mut clients = state.clients.lock().await;
        if let Some(h) = clients.get_mut(&my_uid) {
            let h = Arc::make_mut(h);
            h.pair_wanted_id = session.pair_info.wanted_id;
            h.force_pair_uid = session.force_pair_uid;
            h.pair_info = session.pair_info.clone();
            h.pos = session.pos.clone();
        }
    }

    // Update last_speaker in area
    {
        let mut area = state.areas[session.area_idx].write().await;
        area.last_speaker = session.char_id;
    }

    // Parrot mode
    if session.is_parrot() {
        // No parrot list in this version; just silently mute
        return;
    }
    // Narrator mode: blank out char_id field
    if session.narrator {
        args[3] = String::new();
    }

    // Shadowmute: send the packet only back to the sender so they think it worked.
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if shadowmuted {
        session.send_packet("MS", &arg_refs);
        return;
    }

    // Censor check: if enabled and the decoded message contains a censored word,
    // treat it like a shadowmute — the sender sees it succeed, others don't get it.
    if state.config.censor.enabled {
        let msg_text = ao_decode(&args[4]);
        let msg_lower = msg_text.to_lowercase();
        let censored = {
            let rdata = state.reloadable.read().await;
            !rdata.censor_words.is_empty()
                && rdata.censor_words.iter().any(|w| msg_lower.contains(w.as_str()))
        };
        if censored {
            session.send_packet("MS", &arg_refs);
            return;
        }
    }

    // Broadcast to area, skipping receivers who have ignored the sender.
    let sender_uid = session.uid.unwrap_or(u32::MAX);
    debug!("MS broadcast uid={} area={} fields={} packet=MS#{}#%", sender_uid, session.area_idx, arg_refs.len(), arg_refs.join("#"));
    state.broadcast_to_area_from(session.area_idx, sender_uid, "MS", &arg_refs).await;
}

/// MC#song_or_area#char_id#...%
async fn handle_mc(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    let char_id_str = session.char_id.map(|id| id.to_string()).unwrap_or_default();
    if pkt.body[1] != char_id_str {
        return;
    }
    let name = ao_decode(&pkt.body[0]);

    let is_music = {
        let rdata = state.reloadable.read().await;
        rdata.music.contains(&pkt.body[0].to_string())
    };
    if is_music {
        // Music change
        if !session.rl_mc.try_consume() {
            return;
        }
        if !session.can_change_music() {
            session.server_message(&state.config.server.name, "You are not allowed to change the music here.");
            return;
        }
        let song = if !name.contains('.') {
            // Category selected → stop music
            "~stop.mp3"
        } else {
            &pkt.body[0]
        };
        let display_name = pkt.body.get(2).map(|s| s.as_str()).unwrap_or(&session.showname);
        let effects = pkt.body.get(3).map(|s| s.as_str()).unwrap_or("0");
        state.broadcast_to_area(session.area_idx, "MC", &[song, &char_id_str, display_name, "1", "0", effects]).await;
    } else {
        // Area change
        let mut found_idx = None;
        for (i, area_arc) in state.areas.iter().enumerate() {
            let area = area_arc.read().await;
            if area.name == name || ao_encode(&area.name) == pkt.body[0] {
                found_idx = Some(i);
                break;
            }
        }

        if let Some(new_idx) = found_idx {
            if new_idx == session.area_idx {
                return;
            }
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
            crate::commands::registry::change_area(session, state, new_idx).await;
        }
    }
}

/// HP#bar#value%
async fn handle_hp(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    if !session.can_judge() {
        session.server_message(&state.config.server.name, "You are not allowed to change the HP bars here.");
        return;
    }
    let bar: i32 = match pkt.body[0].parse() { Ok(n) => n, Err(_) => return };
    let value: i32 = match pkt.body[1].parse() { Ok(n) => n, Err(_) => return };
    let ok = {
        let mut area = state.areas[session.area_idx].write().await;
        area.set_hp(bar, value)
    };
    if ok {
        state.broadcast_to_area(session.area_idx, "HP", &[&pkt.body[0], &pkt.body[1]]).await;
    }
}

/// RT#type[#subtype]%
async fn handle_rt(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    if !session.can_judge() {
        session.server_message(&state.config.server.name, "You are not allowed to use WT/CE here.");
        return;
    }
    if pkt.body.len() >= 2 {
        state.broadcast_to_area(session.area_idx, "RT", &[&pkt.body[0], &pkt.body[1]]).await;
    } else {
        state.broadcast_to_area(session.area_idx, "RT", &[&pkt.body[0]]).await;
    }
}

/// CT#username#message%
async fn handle_ct(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    if !session.rl_ct.try_consume() {
        return;
    }
    let username = ao_decode(pkt.body[0].trim());
    if username.is_empty()
        || username == state.config.server.name
        || username.len() > 30
        || username.contains('[')
        || username.contains(']')
    {
        session.server_message(&state.config.server.name, "Invalid username.");
        return;
    }
    let message = &pkt.body[1];
    if message.len() > state.config.server.max_message_len {
        session.server_message(&state.config.server.name, "Your message exceeds the maximum length.");
        return;
    }
    if message.trim().is_empty() {
        return;
    }

    // Check for duplicate OOC name
    {
        let clients = state.clients.lock().await;
        let uid = session.uid.unwrap_or(u32::MAX);
        for handle in clients.values() {
            // We can't check OOC name in other sessions (cross-task).
            // In a simple implementation, OOC name conflicts are best-effort.
        }
    }
    session.ooc_name = username.clone();

    // Command dispatch
    if let Some(rest) = message.strip_prefix('/') {
        let decoded = ao_decode(rest);
        let mut parts = decoded.split_whitespace();
        let command = parts.next().unwrap_or("").to_lowercase();
        let args: Vec<String> = parts.map(|s| s.to_string()).collect();
        dispatch_command(session, state, &command, args).await;
        return;
    }

    if !session.can_speak_ooc() {
        session.server_message(&state.config.server.name, "You are muted from OOC.");
        return;
    }

    let encoded_name = ao_encode(&username);

    // Shadowmute: send OOC only back to sender so they think it worked.
    if session.is_shadowmuted() {
        session.send_packet("CT", &[&encoded_name, message, "0"]);
        return;
    }

    let sender_uid = session.uid.unwrap_or(u32::MAX);
    state.broadcast_to_area_from(session.area_idx, sender_uid, "CT", &[&encoded_name, message, "0"]).await;
}

/// PE#name#description#image%
async fn handle_pe(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    if !session.rl_evi.try_consume() {
        return;
    }
    if !can_alter_evidence(session, state).await {
        session.server_message(&state.config.server.name, "You are not allowed to alter evidence here.");
        return;
    }
    let evi_str = format!("{}&{}&{}", pkt.body[0], pkt.body[1], pkt.body[2]);
    let evi = {
        let mut area = state.areas[session.area_idx].write().await;
        area.evidence.push(evi_str);
        area.evidence.clone()
    };
    let refs: Vec<&str> = evi.iter().map(|s| s.as_str()).collect();
    state.broadcast_to_area(session.area_idx, "LE", &refs).await;
}

/// DE#index%
async fn handle_de(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    if !session.rl_evi.try_consume() {
        return;
    }
    if !can_alter_evidence(session, state).await {
        session.server_message(&state.config.server.name, "You are not allowed to alter evidence here.");
        return;
    }
    let idx: usize = match pkt.body[0].parse() { Ok(n) => n, Err(_) => return };
    let evi = {
        let mut area = state.areas[session.area_idx].write().await;
        if idx >= area.evidence.len() { return; }
        area.evidence.remove(idx);
        area.evidence.clone()
    };
    let refs: Vec<&str> = evi.iter().map(|s| s.as_str()).collect();
    state.broadcast_to_area(session.area_idx, "LE", &refs).await;
}

/// EE#index#name#description#image%
async fn handle_ee(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    if !session.rl_evi.try_consume() {
        return;
    }
    if !can_alter_evidence(session, state).await {
        session.server_message(&state.config.server.name, "You are not allowed to alter evidence here.");
        return;
    }
    let idx: usize = match pkt.body[0].parse() { Ok(n) => n, Err(_) => return };
    let new_evi = format!("{}&{}&{}", pkt.body[1], pkt.body[2], pkt.body[3]);
    let evi = {
        let mut area = state.areas[session.area_idx].write().await;
        if idx >= area.evidence.len() { return; }
        area.evidence[idx] = new_evi;
        area.evidence.clone()
    };
    let refs: Vec<&str> = evi.iter().map(|s| s.as_str()).collect();
    state.broadcast_to_area(session.area_idx, "LE", &refs).await;
}

/// ZZ#reason%
async fn handle_zz(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    if !session.zz_cooldown.is_zero() {
        if let Some(last) = session.last_zz {
            if last.elapsed() < session.zz_cooldown {
                let remaining = session.zz_cooldown.saturating_sub(last.elapsed());
                session.server_message(
                    &state.config.server.name,
                    &format!("Please wait {} more second(s) before calling a mod again.", remaining.as_secs() + 1),
                );
                return;
            }
        }
    }
    session.last_zz = Some(std::time::Instant::now());
    let reason = pkt.body.get(0).map(|s| s.as_str()).unwrap_or("");
    let char_name = {
        let rdata = state.reloadable.read().await;
        session.char_id
            .and_then(|id| rdata.characters.get(id).cloned())
            .unwrap_or_else(|| "Spectator".to_string())
    };
    let area_name = {
        let area = state.areas[session.area_idx].read().await;
        area.name.clone()
    };
    let uid = session.uid.unwrap_or(0);
    let modcall_msg = format!(
        "MODCALL\n----------\nArea: {}\nUser: [{}] {}\nIPID: {}\nReason: {}",
        area_name, uid, char_name, session.ipid, reason
    );
    let clients = state.clients.lock().await;
    for handle in clients.values() {
        if handle.authenticated {
            handle.send_packet("ZZ", &[&modcall_msg]);
        }
    }
}

/// SETCASE#...%
fn handle_setcase(session: &mut ClientSession, pkt: &Packet) {
    for (i, body) in pkt.body[2..].iter().take(5).enumerate() {
        let b: bool = body.parse().unwrap_or(false);
        session.case_prefs[i] = b;
    }
}

/// CASEA#...%
async fn handle_casea(session: &mut ClientSession, state: &Arc<ServerState>, pkt: &Packet) {
    let is_cm = {
        let area = state.areas[session.area_idx].read().await;
        area.has_cm(session.uid.unwrap_or(0))
    };
    if session.char_id.is_none() || !is_cm {
        session.server_message(&state.config.server.name, "You are not allowed to send case alerts here.");
        return;
    }
    let char_name = {
        let rdata = state.reloadable.read().await;
        session.char_id
            .and_then(|id| rdata.characters.get(id).cloned())
            .unwrap_or_else(|| "Spectator".to_string())
    };
    let area_name = {
        let area = state.areas[session.area_idx].read().await;
        area.name.clone()
    };
    let roles = &pkt.body[0];
    let prefs = &pkt.body[1..];
    let announcement = format!(
        "CASE ANNOUNCEMENT: {} in {} needs players for {}",
        char_name, area_name, roles
    );
    let packet_str = format!("CASEA#{}#{}#1#%", announcement, prefs.join("#"));
    let clients = state.clients.lock().await;
    for handle in clients.values() {
        for (i, pref) in prefs.iter().take(5).enumerate() {
            let wants: bool = pref.parse().unwrap_or(false);
            if wants && session.case_prefs.get(i).copied().unwrap_or(false) {
                handle.send(&packet_str);
                break;
            }
        }
    }
}

/// Check if client can alter evidence in their area.
async fn can_alter_evidence(session: &ClientSession, state: &Arc<ServerState>) -> bool {
    use crate::game::areas::EvidenceMode;
    if session.char_id.is_none() {
        return false;
    }
    let area = state.areas[session.area_idx].read().await;
    match area.evi_mode {
        EvidenceMode::Any => true,
        EvidenceMode::CMs => {
            area.has_cm(session.uid.unwrap_or(0)) || perms::has(session.permissions, perms::MOD_EVI)
        }
        EvidenceMode::Mods => {
            perms::has(session.permissions, perms::MOD_EVI)
        }
    }
}

/// Main client loop. Called once per connection from the network layer.
///
/// Sends the handshake greeting, reads packets until disconnect, and
/// cleans up area/UID state when the client leaves.
pub async fn run_client(
    mut transport: crate::network::AoTransport,
    real_ip: std::net::IpAddr,
    state: Arc<ServerState>,
) {
    use tokio::sync::mpsc;

    // Outbound channel: all sends from handlers go here; write task forwards to transport.
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Compute IPID from the real IP (privacy layer: raw IP is dropped after this).
    let ipid = state.privacy.compute_ipid(&real_ip.to_string());
    drop(real_ip); // never referenced again

    // Create per-client session (lives on this task only).
    let mut session = ClientSession::new(ipid, tx, &state.config.rate_limits);

    // Send handshake greeting.
    if let Err(e) = transport.send("decryptor#NOENCRYPT#%").await {
        debug!("Failed to send decryptor: {}", e);
        return;
    }

    // Keepalive ping timer (WebSocket only).
    let ping_interval_secs = state.config.network.ws_ping_interval_secs;
    let ping_timeout_secs = state.config.network.ws_ping_timeout_secs;
    let use_keepalive = ping_interval_secs > 0;

    let mut ping_timer = tokio::time::interval(
        std::time::Duration::from_secs(if use_keepalive { ping_interval_secs } else { 30 }),
    );
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the first immediate tick so the ping doesn't fire at time 0.
    ping_timer.tick().await;

    // Drive read and write concurrently within the same task.
    loop {
        tokio::select! {
            // Forward outbound messages — intercept internal control messages.
            Some(msg) = rx.recv() => {
                // Internal cross-task control messages start with "__".
                // Do NOT send them to the wire; dispatch them locally.
                if msg.starts_with("__") {
                    // Strip the trailing "#%" if present before using as header.
                    let header = msg.trim_end_matches("#%").trim_end_matches('#');
                    handle_internal(&mut session, &state, header).await;
                    continue;
                }
                if let Err(e) = transport.send(&msg).await {
                    debug!("Send error: {}", e);
                    break;
                }
            }

            // Process inbound packets.
            result = transport.recv_packet() => {
                match result {
                    None => break, // clean disconnect
                    Some(Err(e)) => {
                        debug!("Recv error: {}", e);
                        break;
                    }
                    Some(Ok(pkt)) => {
                        dispatch(&mut session, &state, pkt).await;
                    }
                }
            }

            // Keepalive ping tick (WebSocket only).
            _ = ping_timer.tick(), if use_keepalive => {
                if ping_timeout_secs > 0 {
                    let timeout = std::time::Duration::from_secs(ping_timeout_secs);
                    if transport.is_stale(timeout) {
                        debug!("WS keepalive timeout for IPID={}", session.ipid);
                        break;
                    }
                }
                let _ = transport.keepalive_ping().await;
            }
        }
    }

    // Cleanup: release character slot, decrement player count, free UID.
    if let Some(uid) = session.uid {
        // Release character and capture taken strings for CharsCheck broadcast.
        let area_idx = session.area_idx;
        let chars_check_taken: Option<Vec<String>> = if let Some(char_id) = session.char_id {
            let taken_strings = {
                let mut area = state.areas[area_idx].write().await;
                if char_id < area.taken.len() {
                    area.taken[char_id] = false;
                }
                area.players = area.players.saturating_sub(1);
                area.cms.retain(|&c| c != uid);
                area.taken_strings()
            };
            Some(taken_strings)
        } else {
            // No character — still decrement player count for the area.
            let mut area = state.areas[area_idx].write().await;
            area.players = area.players.saturating_sub(1);
            area.cms.retain(|&c| c != uid);
            None
        };

        // Remove from client list.
        state.remove_client(uid).await;
        state.player_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let _ = state.player_watch_tx.send(state.player_count());
        state.free_uid(uid).await;

        // Broadcast CharsCheck to area so remaining clients update their char lists.
        if let Some(taken) = chars_check_taken {
            let refs: Vec<&str> = taken.iter().map(|s| s.as_str()).collect();
            state.broadcast_to_area(area_idx, "CharsCheck", &refs).await;
        }

        // Broadcast updated ARUP.
        state.send_player_arup().await;
        state.send_cm_arup().await;

        info!("Client UID={} disconnected (IPID={})", uid, session.ipid);
    }
}
