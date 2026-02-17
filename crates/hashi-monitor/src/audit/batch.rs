use crate::config::Config;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;

/// A batch auditor that validates all events emitted during a given time period [t1, t2].
/// Note that the auditor looks back and beyond the input range a little, e.g., to find predecessor of an event@t1.
pub struct BatchAuditor {
    pub cfg: Config,
    pub start: UnixSeconds,
    pub end: UnixSeconds,
}

impl BatchAuditor {
    pub fn new(cfg: Config, t1: UnixSeconds, t2: UnixSeconds) -> anyhow::Result<Self> {
        anyhow::ensure!(t1 <= t2, "invalid time range: t1={t1} > t2={t2}");
        Ok(Self {
            cfg,
            start: t1,
            end: t2,
        })
    }

    pub fn in_window(&self, e: &WithdrawalEvent) -> bool {
        e.timestamp >= self.start && e.timestamp <= self.end
    }

    pub fn run(&self) -> anyhow::Result<()> {
        todo!("implement me")
    }
}
