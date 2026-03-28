use std::time::{Duration, Instant};
use tokio::sync::mpsc::{self, Sender};

use crate::ratelimit::TokenBucket;

/// Mute state for a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MuteState {
    #[default]
    None,
    Ic,
    Ooc,
    IcOoc,
    Music,
    Judge,
    Parrot,
    /// Shadowmute: the victim thinks their messages are going through, but
    /// nobody else sees them. No notification is sent to the victim.
    Shadowmute,
}

impl MuteState {
    pub fn display(&self) -> &'static str {
        match self {
            MuteState::None => "",
            MuteState::Ic => "IC",
            MuteState::Ooc => "OOC",
            MuteState::IcOoc => "IC/OOC",
            MuteState::Music => "from changing the music",
            MuteState::Judge => "from judge controls",
            MuteState::Parrot => "parroted",
            MuteState::Shadowmute => "shadowmuted",
        }
    }
}

/// Pairing information stored per client.
#[derive(Debug, Clone, Default)]
pub struct PairInfo {
    pub char_name: String,
    pub emote: String,
    pub flip: String,
    pub offset: String,
    pub wanted_id: Option<usize>,
}

/// The per-client state. Lives in one tokio task only.
pub struct ClientSession {
    // Identity
    pub uid: Option<u32>,
    /// HMAC-SHA256 hashed HDID
    pub hdid: Option<String>,
    /// HMAC-SHA256 hashed IP (daily rotating)
    pub ipid: String,

    // Handshake state
    pub joining: bool,

    // Auth
    pub authenticated: bool,
    pub permissions: u64,
    pub mod_name: Option<String>,

    // Game state
    pub area_idx: usize,
    pub char_id: Option<usize>,
    pub ooc_name: String,
    pub last_msg: String,
    pub showname: String,
    pub pos: String,

    // Pairing
    pub pair_info: PairInfo,
    /// UID of a confirmed force-pair partner (set by /pair when mutual, cleared by /unpair).
    pub force_pair_uid: Option<u32>,

    // Mute
    pub mute_state: MuteState,
    pub mute_until: Option<Instant>,
    pub warn_count: u32,

    // Private messaging
    /// UID of the last player who sent this client a PM (for /r reply).
    pub last_pm_uid: Option<u32>,

    // Case preferences (5 roles)
    pub case_prefs: [bool; 5],

    // Narrator mode
    pub narrator: bool,

    // Rate limiters (per-client token buckets)
    pub rl_ic: TokenBucket,
    pub rl_mc: TokenBucket,
    pub rl_ct: TokenBucket,
    pub rl_evi: TokenBucket,
    /// Cooldown for ZZ (mod call): stores the time of the last call.
    pub last_zz: Option<Instant>,
    /// Duration between allowed mod calls (from config).
    pub zz_cooldown: Duration,

    // Outbound message sender (bounded — provides backpressure against slow clients).
    pub tx: Sender<String>,
}

impl ClientSession {
    pub fn new(
        ipid: String,
        tx: Sender<String>,
        rl: &crate::config::RateLimitsConfig,
    ) -> Self {
        Self {
            uid: None,
            hdid: None,
            ipid,
            joining: false,
            authenticated: false,
            permissions: 0,
            mod_name: None,
            area_idx: 0,
            char_id: None,
            ooc_name: String::new(),
            last_msg: String::new(),
            showname: String::new(),
            pos: String::new(),
            pair_info: PairInfo { wanted_id: None, ..Default::default() },
            force_pair_uid: None,
            mute_state: MuteState::None,
            mute_until: None,
            warn_count: 0,
            last_pm_uid: None,
            case_prefs: [false; 5],
            narrator: false,
            rl_ic: TokenBucket::new(rl.ic_rate, rl.ic_burst),
            rl_mc: TokenBucket::new(rl.mc_rate, rl.mc_burst),
            rl_ct: TokenBucket::new(rl.ct_rate, rl.ct_burst),
            rl_evi: TokenBucket::new(rl.evidence_rate, rl.evidence_burst),
            last_zz: None,
            zz_cooldown: Duration::from_secs(rl.zz_cooldown_secs),
            tx,
        }
    }

    /// Send a raw wire-format string to this client.
    /// Uses `try_send`; if the outbound channel is full the packet is silently
    /// dropped (the client will be cleaned up by the keepalive timeout).
    pub fn send_raw(&self, msg: impl Into<String>) {
        let _ = self.tx.try_send(msg.into());
    }

    /// Send a packet.
    pub fn send_packet(&self, header: &str, args: &[&str]) {
        let msg = if args.is_empty() {
            format!("{}#%", header)
        } else {
            format!("{}#{}#%", header, args.join("#"))
        };
        self.send_raw(msg);
    }

    /// Send a server OOC message.
    pub fn server_message(&self, server_name: &str, text: &str) {
        let encoded_name = crate::protocol::packet::ao_encode(server_name);
        let encoded_text = crate::protocol::packet::ao_encode(text);
        self.send_packet("CT", &[&encoded_name, &encoded_text, "1"]);
    }

    /// Check if the mute has expired; if so, reset to None. Returns true if still muted.
    pub fn check_mute(&mut self) -> bool {
        if let Some(until) = self.mute_until {
            if Instant::now() >= until {
                self.mute_state = MuteState::None;
                self.mute_until = None;
                return false;
            }
        }
        self.mute_state != MuteState::None
    }

    pub fn can_speak_ic(&mut self) -> bool {
        if self.char_id.is_none() {
            return false;
        }
        // Shadowmuted: let the handler decide (victim sees their own message).
        if self.mute_state == MuteState::Shadowmute {
            return true;
        }
        if matches!(self.mute_state, MuteState::Ic | MuteState::IcOoc) {
            return !self.check_mute();
        }
        true
    }

    pub fn can_speak_ooc(&mut self) -> bool {
        // Shadowmuted: let the handler decide (victim sees their own message).
        if self.mute_state == MuteState::Shadowmute {
            return true;
        }
        if matches!(self.mute_state, MuteState::Ooc | MuteState::IcOoc) {
            return !self.check_mute();
        }
        true
    }

    /// Returns true if this client is shadowmuted.
    pub fn is_shadowmuted(&self) -> bool {
        self.mute_state == MuteState::Shadowmute
    }

    pub fn can_change_music(&mut self) -> bool {
        if self.char_id.is_none() {
            return false;
        }
        if matches!(self.mute_state, MuteState::Music | MuteState::Ic | MuteState::IcOoc) {
            return !self.check_mute();
        }
        true
    }

    pub fn can_judge(&mut self) -> bool {
        if self.char_id.is_none() {
            return false;
        }
        if matches!(self.mute_state, MuteState::Judge | MuteState::Ic | MuteState::IcOoc) {
            return !self.check_mute();
        }
        true
    }

    pub fn is_parrot(&mut self) -> bool {
        if self.mute_state == MuteState::Parrot {
            return self.check_mute();
        }
        false
    }
}
