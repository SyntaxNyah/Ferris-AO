use serde::Deserialize;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceMode {
    Any,
    CMs,
    Mods,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Idle,
    LookingForPlayers,
    Casing,
    Recess,
    Rp,
    Gaming,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Idle => "IDLE",
            Status::LookingForPlayers => "LOOKING-FOR-PLAYERS",
            Status::Casing => "CASING",
            Status::Recess => "RECESS",
            Status::Rp => "RP",
            Status::Gaming => "GAMING",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Free,
    Spectatable,
    Locked,
}

impl LockState {
    pub fn as_str(&self) -> &'static str {
        match self {
            LockState::Free => "FREE",
            LockState::Spectatable => "SPECTATABLE",
            LockState::Locked => "LOCKED",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AreaConfig {
    pub name: String,
    pub background: String,
    pub evidence_mode: String,
    pub allow_iniswap: bool,
    pub allow_cms: bool,
    pub force_nointerrupt: bool,
    pub force_bglist: bool,
    pub lock_bg: bool,
    pub lock_music: bool,
}

#[derive(Debug, Deserialize)]
pub struct AreasFile {
    pub area: Vec<AreaConfig>,
}

pub struct Area {
    // Static config
    pub name: String,
    pub default_bg: String,
    pub evi_mode: EvidenceMode,
    pub allow_iniswap: bool,
    pub allow_cms: bool,
    pub force_nointerrupt: bool,
    pub force_bglist: bool,
    pub lock_bg: bool,
    pub lock_music: bool,

    // Mutable state
    pub taken: Vec<bool>,
    pub players: usize,
    pub def_hp: i32,
    pub pro_hp: i32,
    pub evidence: Vec<String>,
    pub cms: Vec<u32>,
    pub lock: LockState,
    pub status: Status,
    pub invited: Vec<u32>,
    pub doc: String,
    pub bg: String,
    pub last_speaker: Option<usize>,
    pub log_buffer: VecDeque<String>,
}

impl Area {
    pub fn new(cfg: &AreaConfig, char_count: usize, log_buf_size: usize) -> Self {
        let evi_mode = match cfg.evidence_mode.to_lowercase().as_str() {
            "any" => EvidenceMode::Any,
            "mods" => EvidenceMode::Mods,
            _ => EvidenceMode::CMs,
        };
        Self {
            name: cfg.name.clone(),
            default_bg: cfg.background.clone(),
            evi_mode,
            allow_iniswap: cfg.allow_iniswap,
            allow_cms: cfg.allow_cms,
            force_nointerrupt: cfg.force_nointerrupt,
            force_bglist: cfg.force_bglist,
            lock_bg: cfg.lock_bg,
            lock_music: cfg.lock_music,

            taken: vec![false; char_count],
            players: 0,
            def_hp: 10,
            pro_hp: 10,
            evidence: Vec::new(),
            cms: Vec::new(),
            lock: LockState::Free,
            status: Status::Idle,
            invited: Vec::new(),
            doc: String::new(),
            bg: cfg.background.clone(),
            last_speaker: None,
            log_buffer: VecDeque::with_capacity(log_buf_size),
        }
    }

    pub fn reset(&mut self) {
        self.cms.clear();
        self.invited.clear();
        self.lock = LockState::Free;
        self.status = Status::Idle;
        self.bg = self.default_bg.clone();
        self.def_hp = 10;
        self.pro_hp = 10;
        self.last_speaker = None;
    }

    /// Returns taken character slots as a list of "1" / "0" strings.
    pub fn taken_strings(&self) -> Vec<String> {
        self.taken.iter().map(|t| if *t { "1".into() } else { "0".into() }).collect()
    }

    /// Try to take a character slot. Returns true if successful (slot was free).
    pub fn take_char(&mut self, id: usize) -> bool {
        if id >= self.taken.len() {
            return false;
        }
        if self.taken[id] {
            return false;
        }
        self.taken[id] = true;
        true
    }

    /// Release a character slot.
    pub fn release_char(&mut self, id: usize) {
        if id < self.taken.len() {
            self.taken[id] = false;
        }
    }

    /// Switch character (release old, take new). Returns true on success.
    pub fn switch_char(&mut self, old: Option<usize>, new: usize) -> bool {
        if new >= self.taken.len() {
            return false;
        }
        if self.taken[new] {
            return false; // Already taken
        }
        if let Some(old_id) = old {
            self.release_char(old_id);
        }
        self.taken[new] = true;
        true
    }

    pub fn is_taken(&self, id: usize) -> bool {
        self.taken.get(id).copied().unwrap_or(false)
    }

    pub fn add_cm(&mut self, uid: u32) {
        if !self.cms.contains(&uid) {
            self.cms.push(uid);
        }
    }

    pub fn remove_cm(&mut self, uid: u32) {
        self.cms.retain(|&c| c != uid);
    }

    pub fn has_cm(&self, uid: u32) -> bool {
        self.cms.contains(&uid)
    }

    pub fn set_hp(&mut self, bar: i32, value: i32) -> bool {
        if value < 0 || value > 10 {
            return false;
        }
        match bar {
            1 => self.def_hp = value,
            2 => self.pro_hp = value,
            _ => return false,
        }
        true
    }

    pub fn add_to_log(&mut self, entry: String, capacity: usize) {
        if self.log_buffer.len() >= capacity {
            self.log_buffer.pop_front();
        }
        self.log_buffer.push_back(entry);
    }
}

pub fn load_areas(path: &std::path::Path, char_count: usize) -> anyhow::Result<Vec<Area>> {
    let content = std::fs::read_to_string(path)?;
    let file: AreasFile = toml::from_str(&content)?;
    if file.area.is_empty() {
        anyhow::bail!("areas.toml must define at least one area");
    }
    Ok(file.area.iter().map(|cfg| Area::new(cfg, char_count, 150)).collect())
}
