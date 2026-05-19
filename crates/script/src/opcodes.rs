pub use bitcoin::blockdata::opcodes::all::*;

/// Project-local opcode wrapper used by future hand-rolled interpreter code.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpCode(u8);

impl OpCode {
    /// Creates an opcode from its consensus byte.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the consensus opcode byte.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl From<bitcoin::blockdata::opcodes::Opcode> for OpCode {
    fn from(opcode: bitcoin::blockdata::opcodes::Opcode) -> Self {
        Self(opcode.to_u8())
    }
}

impl From<OpCode> for bitcoin::blockdata::opcodes::Opcode {
    fn from(opcode: OpCode) -> Self {
        Self::from(opcode.value())
    }
}
