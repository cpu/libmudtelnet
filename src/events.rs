use bytes::{BufMut, Bytes, BytesMut};

use crate::telnet::op_command::{IAC, SB, SE};
use crate::Parser;

/// A struct representing a 2 byte IAC sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Iac {
    pub command: u8,
}

impl From<Iac> for Bytes {
    fn from(iac: Iac) -> Self {
        Bytes::copy_from_slice(&[IAC, iac.command])
    }
}

/// A struct representing a 3 byte IAC sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Negotiation {
    pub command: u8,
    pub option: u8,
}

impl From<Negotiation> for Bytes {
    fn from(negotiation: Negotiation) -> Self {
        Bytes::copy_from_slice(&[IAC, negotiation.command, negotiation.option])
    }
}

/// A struct representing an arbitrary length IAC subnegotiation sequence.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Subnegotiation {
    pub option: u8,
    pub buffer: Bytes,
}

impl From<Subnegotiation> for Bytes {
    fn from(subneg: Subnegotiation) -> Self {
        let head = [IAC, SB, subneg.option];
        let parsed = &Parser::escape_iac(subneg.buffer)[..];
        let tail = [IAC, SE];
        let mut buf = BytesMut::with_capacity(head.len() + parsed.len() + tail.len());
        buf.put(&head[..]);
        buf.put(parsed);
        buf.put(&tail[..]);
        buf.freeze()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Subnegotiation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let option = u.arbitrary()?;
        let buffer: Vec<u8> = u.arbitrary()?;
        Ok(Self {
            option,
            buffer: Bytes::from(buffer),
        })
    }
}

/// An enum representing various telnet events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    /// An IAC command sequence.
    Iac(Iac),
    /// An IAC negotiation sequence.
    Negotiation(Negotiation),
    /// An IAC subnegotiation sequence.
    Subnegotiation(Subnegotiation),
    /// Regular data received from the remote end.
    DataReceive(Bytes),
    /// Deframed line data received from the remote end.
    LineReceive(Bytes),
    /// Any data to be sent to the remote end.
    DataSend(Bytes),
    /// MCCP2/3 compatibility. MUST DECOMPRESS THIS DATA BEFORE PARSING
    DecompressImmediate(Bytes),
}

impl From<Iac> for Event {
    fn from(iac: Iac) -> Self {
        Self::Iac(iac)
    }
}

impl From<Negotiation> for Event {
    fn from(neg: Negotiation) -> Self {
        Self::Negotiation(neg)
    }
}

impl From<Subnegotiation> for Event {
    fn from(sub: Subnegotiation) -> Self {
        Self::Subnegotiation(sub)
    }
}

impl From<Event> for Bytes {
    fn from(event: Event) -> Self {
        match event {
            Event::Iac(iac) => iac.into(),
            Event::Negotiation(neg) => neg.into(),
            Event::Subnegotiation(sub) => sub.into(),
            Event::DataReceive(data)
            | Event::LineReceive(data)
            | Event::DataSend(data)
            | Event::DecompressImmediate(data) => data,
        }
    }
}
