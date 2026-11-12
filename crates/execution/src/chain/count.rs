#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainTxCount(Option<u64>);

impl ChainTxCount {
    pub const UNKNOWN: Self = Self(None);

    #[must_use]
    pub const fn established(count: u64) -> Self {
        Self(Some(count))
    }

    #[must_use]
    pub const fn from_wire(raw: u64) -> Self {
        match raw {
            0 => Self::UNKNOWN,
            count => Self(Some(count)),
        }
    }

    #[must_use]
    pub const fn to_wire(self) -> u64 {
        match self.0 {
            Some(count) => count,
            None => 0,
        }
    }

    #[must_use]
    pub const fn get(self) -> Option<u64> {
        self.0
    }

    #[must_use]
    pub fn advance(self, height: u32, delta: u64) -> Self {
        match self.0 {
            Some(known) => known
                .checked_add(delta)
                .map_or(Self::UNKNOWN, Self::established),
            None if height == 0 => Self::established(delta),
            None => Self::UNKNOWN,
        }
    }

    #[must_use]
    pub fn rewind(self, delta: u64) -> Self {
        match self.0 {
            Some(known) => known
                .checked_sub(delta)
                .map_or(Self::UNKNOWN, Self::established),
            None => Self::UNKNOWN,
        }
    }
}
