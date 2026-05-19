use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hashbrown::HashMap;

use crate::wire::PeerError;

/// Score at which a peer is considered banned.
pub const MAX_BAN_SCORE: u32 = 100;

/// One ban-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    /// Accumulated misbehavior score.
    pub score: u32,
    /// Optional wall-clock expiration time.
    pub banned_until: Option<SystemTime>,
    /// Human-readable reason for the last score increment.
    pub reason: String,
}

impl BanEntry {
    /// Return true when the score and expiry indicate an active ban.
    pub fn is_banned(&self, now: SystemTime) -> bool {
        if self.score < MAX_BAN_SCORE {
            return false;
        }
        self.banned_until.is_none_or(|until| until > now)
    }
}

/// Persistent peer ban list.
#[derive(Debug, Clone)]
pub struct BanList {
    /// Banned or scored IP addresses.
    pub entries: HashMap<IpAddr, BanEntry>,
    path: PathBuf,
}

impl BanList {
    /// Create an empty ban list persisted at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            entries: HashMap::new(),
            path: path.into(),
        }
    }

    /// Load a ban list from a dedicated file.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, PeerError> {
        let path = path.into();
        if !Path::new(&path).exists() {
            return Ok(Self::new(path));
        }

        let mut file = File::open(&path)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;

        let mut list = Self::new(path);
        for line in data.lines().filter(|line| !line.trim().is_empty()) {
            let mut fields = line.splitn(4, '\t');
            let ip = parse_field(&mut fields, line)?
                .parse::<IpAddr>()
                .map_err(|_| PeerError::InvalidBanEntry(line.to_owned()))?;
            let score = parse_field(&mut fields, line)?
                .parse::<u32>()
                .map_err(|_| PeerError::InvalidBanEntry(line.to_owned()))?;
            let until_secs = parse_field(&mut fields, line)?
                .parse::<u64>()
                .map_err(|_| PeerError::InvalidBanEntry(line.to_owned()))?;
            let reason = fields.next().unwrap_or_default().to_owned();
            let banned_until = if until_secs == 0 {
                None
            } else {
                Some(UNIX_EPOCH + Duration::from_secs(until_secs))
            };
            list.entries.insert(
                ip,
                BanEntry {
                    score,
                    banned_until,
                    reason,
                },
            );
        }
        Ok(list)
    }

    /// Persist the ban list to its dedicated file.
    pub fn save(&self) -> Result<(), PeerError> {
        let mut file = File::create(&self.path)?;
        for (ip, entry) in &self.entries {
            let until = entry
                .banned_until
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_secs());
            let reason = entry.reason.replace(['\t', '\n'], " ");
            writeln!(file, "{ip}\t{}\t{until}\t{reason}", entry.score)?;
        }
        Ok(())
    }

    /// Add score to an IP address and optionally set a ban duration.
    pub fn add_score(
        &mut self,
        ip: IpAddr,
        score_delta: u32,
        ban_duration: Option<Duration>,
        reason: impl Into<String>,
    ) {
        let entry = self.entries.entry(ip).or_insert_with(|| BanEntry {
            score: 0,
            banned_until: None,
            reason: String::new(),
        });
        entry.score = entry.score.saturating_add(score_delta);
        entry.reason = reason.into();
        if entry.score >= MAX_BAN_SCORE {
            entry.banned_until = ban_duration.map(|duration| SystemTime::now() + duration);
        }
    }

    /// Return true when `ip` is actively banned.
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        self.entries
            .get(ip)
            .is_some_and(|entry| entry.is_banned(SystemTime::now()))
    }

    /// Remove expired bans while leaving non-banned scores intact.
    pub fn clear_expired(&mut self) {
        let now = SystemTime::now();
        self.entries
            .retain(|_ip, entry| entry.banned_until.is_none_or(|until| until > now));
    }
}

fn parse_field<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
    line: &str,
) -> Result<&'a str, PeerError> {
    fields
        .next()
        .ok_or_else(|| PeerError::InvalidBanEntry(line.to_owned()))
}
