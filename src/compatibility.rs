use core::fmt::{Debug, Formatter};

/// An expansion of a bitmask contained in `CompatibilityTable`.
#[derive(Default, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Entry(u8);

impl Entry {
    #[must_use]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn new(local: bool, remote: bool, local_state: bool, remote_state: bool) -> Self {
        let mut entry = Self::default();
        if local {
            entry.set_local_support();
        }
        if remote {
            entry.set_remote_support();
        }
        if local_state {
            entry.set_local_enabled();
        }
        if remote_state {
            entry.set_remote_enabled();
        }
        entry
    }

    #[must_use]
    pub fn local_support(&self) -> bool {
        self.0 & Table::ENABLED_LOCAL == Table::ENABLED_LOCAL
    }

    pub fn set_local_support(&mut self) {
        self.0 |= Table::ENABLED_LOCAL;
    }

    pub fn clear_local_support(&mut self) {
        self.0 &= !Table::ENABLED_LOCAL;
    }

    #[must_use]
    pub fn remote_support(&self) -> bool {
        self.0 & Table::ENABLED_REMOTE == Table::ENABLED_REMOTE
    }

    pub fn set_remote_support(&mut self) {
        self.0 |= Table::ENABLED_REMOTE;
    }

    pub fn clear_remote_support(&mut self) {
        self.0 &= !Table::ENABLED_REMOTE;
    }

    #[must_use]
    pub fn local_enabled(&self) -> bool {
        self.0 & Table::LOCAL_STATE == Table::LOCAL_STATE
    }

    pub fn set_local_enabled(&mut self) {
        self.0 |= Table::LOCAL_STATE;
    }

    pub fn clear_local_enabled(&mut self) {
        self.0 &= !Table::LOCAL_STATE;
    }

    #[must_use]
    pub fn remote_enabled(&self) -> bool {
        self.0 & Table::REMOTE_STATE == Table::REMOTE_STATE
    }

    pub fn set_remote_enabled(&mut self) {
        self.0 |= Table::REMOTE_STATE;
    }

    pub fn clear_remote_enabled(&mut self) {
        self.0 &= !Table::REMOTE_STATE;
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

impl Debug for Entry {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("value", &self.0)
            .field("local_support", &self.local_support())
            .field("local_enabled", &self.local_enabled())
            .field("remote_support", &self.remote_support())
            .field("remote_enabled", &self.remote_enabled())
            .finish()
    }
}

/// A table of options that are supported locally or remotely, and their current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    options: [Entry; TABLE_SIZE],
}

impl Default for Table {
    fn default() -> Self {
        Self {
            options: [Entry::default(); TABLE_SIZE],
        }
    }
}

impl Table {
    /// Option is locally supported.
    pub const ENABLED_LOCAL: u8 = 1;
    /// Option is remotely supported.
    pub const ENABLED_REMOTE: u8 = 1 << 1;
    /// Option is currently enabled locally.
    pub const LOCAL_STATE: u8 = 1 << 2;
    /// Option is currently enabled remotely.
    pub const REMOTE_STATE: u8 = 1 << 3;

    const DEFINED_FLAGS: u8 =
        Self::ENABLED_LOCAL | Self::ENABLED_REMOTE | Self::LOCAL_STATE | Self::REMOTE_STATE;

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a table with some option values set.
    ///
    /// # Arguments
    ///
    /// `values` - A slice of `(u8, u8)` tuples. The first value is the option code, and the second is the bitmask value for that option.
    ///
    /// # Notes
    ///
    /// An option bitmask can be generated using [`Entry::new`].
    #[must_use]
    pub fn from_options(values: &[(u8, u8)]) -> Self {
        let mut options = [Entry::default(); TABLE_SIZE];
        for (opt, val) in values {
            options[*opt as usize] = Entry(*val & Self::DEFINED_FLAGS);
        }
        Self { options }
    }

    /// Enable local support for an option.
    pub fn support_local(&mut self, option: u8) {
        self.option_mut(option).set_local_support();
    }

    /// Enable remote support for an option.
    pub fn support_remote(&mut self, option: u8) {
        self.option_mut(option).set_remote_support();
    }

    /// Enable both remote and local support for an option.
    pub fn support(&mut self, option: u8) {
        let entry = self.option_mut(option);
        entry.set_local_support();
        entry.set_remote_support();
    }

    #[must_use]
    pub fn option_mut(&mut self, option: u8) -> &mut Entry {
        &mut self.options[option as usize]
    }

    #[must_use]
    pub fn option(&self, option: u8) -> &Entry {
        &self.options[option as usize]
    }

    /// Reset all negotiated states
    pub fn reset_states(&mut self) {
        for opt in &mut self.options {
            opt.clear_local_enabled();
            opt.clear_remote_enabled();
        }
    }
}

impl From<u8> for Entry {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Entry> for u8 {
    fn from(value: Entry) -> Self {
        value.0
    }
}

#[cfg(test)]
mod test_compat {
    use super::*;
    use crate::telnet::op_option::GMCP;

    #[test]
    fn test_reset() {
        let mut table = Table::default();
        let entry = Entry::new(true, true, true, true);
        assert!(entry.remote_support());
        assert!(entry.local_support());
        assert!(entry.remote_enabled());
        assert!(entry.local_enabled());
        *table.option_mut(GMCP) = entry;
        table.reset_states();
        let entry = table.option(GMCP);
        assert!(entry.remote_support());
        assert!(entry.local_support());
        assert!(!entry.remote_enabled());
        assert!(!entry.local_enabled());
    }
}

const TABLE_SIZE: usize = 1 + u8::MAX as usize;
