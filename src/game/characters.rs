use std::path::Path;
use anyhow::Result;

pub fn load_lines(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    let lines: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    Ok(lines)
}

/// Build the SM packet body: area names first, then music entries.
/// Format: `SM#area1#area2#...#song1#song2#...#%`
/// If music list doesn't start with a category (first entry has '.'), prepend "Songs".
pub fn build_sm_packet(area_names: &[&str], music: &[String]) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(area_names.len() + music.len() + 1);

    for name in area_names {
        parts.push(name);
    }

    // If first music entry looks like a filename (contains '.'), add a category header
    let mut music_refs: Vec<&str> = music.iter().map(|s| s.as_str()).collect();
    if music_refs.first().map(|s| s.contains('.')).unwrap_or(false) {
        parts.push("Songs");
    }
    parts.extend_from_slice(&music_refs[..]);

    format!("SM#{}#%", parts.join("#"))
}
