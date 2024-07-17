#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
extern crate core;
#[cfg(feature = "std")]
extern crate std as alloc;

pub mod compatibility;
pub mod events;
pub mod telnet;

use alloc::vec::Vec;
use alloc::{format, vec};
#[cfg(feature = "tokio-util")]
use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
#[cfg(feature = "tokio-util")]
use tokio_util::codec::Decoder;

use compatibility::{Entry, Table};
use events::{Event, Iac, Negotiation, Subnegotiation};
use telnet::op_command::{DO, DONT, EOR, GA, IAC, NOP, SB, SE, WILL, WONT};

enum EventType {
    None(Bytes),
    Iac(Bytes),
    SubNegotiation(Bytes, Option<Bytes>),
    Neg(Bytes),
}

/// A telnet parser that handles the main parts of the protocol.
pub struct Parser {
    pub options: Table,
    pub deframe_lines: bool,
    buffer: BytesMut,
    line_buffer: BytesMut,
}

impl Default for Parser {
    fn default() -> Self {
        Parser::with_capacity(128)
    }
}

impl Parser {
    /// Create a default, empty Parser with an internal buffer capacity of 128 bytes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty parser, setting the initial internal buffer capcity.
    #[must_use]
    pub fn with_capacity(size: usize) -> Self {
        Self::with_support_and_capacity(Table::default(), size)
    }

    /// Create a parser, directly supplying a `CompatibilityTable`.
    ///
    /// Uses the default initial buffer capacity of 128 bytes.
    #[must_use]
    pub fn with_support(table: Table) -> Self {
        Self::with_support_and_capacity(table, 128)
    }

    /// Create a parser, setting the initial internal buffer capacity and directly
    /// supplying a `CompatibilityTable`.
    #[must_use]
    pub fn with_support_and_capacity(table: Table, size: usize) -> Self {
        Self {
            options: table,
            buffer: BytesMut::with_capacity(size),
            deframe_lines: false,
            line_buffer: BytesMut::with_capacity(size),
        }
    }

    /// Receive bytes into the internal buffer.
    ///
    /// # Arguments
    ///
    /// * `data` - The bytes to be received. This should be sourced from the remote side of a connection.
    ///
    /// # Returns
    ///
    /// `Vec<TelnetEvents>` - Any events parsed from the internal buffer with the new bytes.
    ///
    pub fn receive(&mut self, data: impl AsRef<[u8]>) -> Vec<Event> {
        self.buffer.put(data.as_ref());
        self.process()
    }

    /// Get whether the remote end supports and is using linemode.
    pub fn linemode_enabled(&mut self) -> bool {
        let opt = self.options.option(telnet::op_option::LINEMODE);
        opt.remote_support() && opt.remote_enabled()
    }

    /// Escape IAC bytes in data that is to be transmitted and treated as a non-IAC sequence.
    ///
    /// # Example
    /// `[255, 1, 6, 2]` -> `[255, 255, 1, 6, 2]`
    pub fn escape_iac<T>(data: T) -> Bytes
    where
        Bytes: From<T>,
    {
        let data = Bytes::from(data);
        let mut res = BytesMut::with_capacity(data.len());
        for byte in data {
            res.put_u8(byte);
            if byte == IAC {
                res.put_u8(IAC);
            }
        }
        res.freeze()
    }

    /// Reverse escaped IAC bytes for non-IAC sequences and data.
    ///
    /// # Example
    /// `[255, 255, 1, 6, 2]` -> `[255, 1, 6, 2]`
    pub fn unescape_iac<T>(data: T) -> Bytes
    where
        Bytes: From<T>,
    {
        #[derive(Debug, Clone, Copy)]
        enum States {
            Normal,
            Iac,
        }

        let data = Bytes::from(data);
        let mut res = BytesMut::with_capacity(data.len());

        let mut state = States::Normal;
        let mut out_val;
        for val in data {
            (state, out_val) = match (state, val) {
                (States::Normal, IAC) => (States::Iac, Some(val)),
                (States::Iac, IAC) => (States::Normal, None),
                (States::Normal | States::Iac, _) => (States::Normal, Some(val)),
            };
            if let Some(val) = out_val {
                res.put_u8(val);
            }
        }

        res.freeze()
    }

    /// Negotiate an option.
    ///
    /// # Arguments
    ///
    /// `command` - A `u8` representing the telnet command code to be negotiated with. Example: WILL (251), WONT (252), DO (253), DONT (254)
    ///
    /// `option` - A `u8` representing the telnet option code that is being negotiated.
    ///
    /// # Returns
    ///
    /// `TelnetEvents::DataSend` - A `DataSend` event to be processed.
    ///
    /// # Usage
    ///
    /// This and other methods meant for sending data to the remote end will generate a `TelnetEvents::Send(DataEvent)` event.
    ///
    /// These Send events contain a buffer that should be sent directly to the remote end, as it will have already been encoded properly.
    pub fn negotiate(&mut self, command: u8, option: u8) -> Event {
        Event::DataSend(Negotiation { command, option }.into())
    }

    /// Indicate to the other side that you are able and wanting to utilize an option.
    ///
    /// # Arguments
    ///
    /// `option` - A `u8` representing the telnet option code that you want to enable locally.
    ///
    /// # Returns
    ///
    /// `Option<TelnetEvents::DataSend>` - The `DataSend` event to be processed, or None if not supported.
    ///
    /// # Notes
    ///
    /// This method will do nothing if the option is not "supported" locally via the `CompatibilityTable`.
    pub fn _will(&mut self, option: u8) -> Option<Event> {
        let opt = self.options.option_mut(option);
        if !opt.local_support() || opt.local_enabled() {
            return None;
        }
        opt.set_local_enabled();
        Some(self.negotiate(WILL, option))
    }

    /// Indicate to the other side that you are not wanting to utilize an option.
    ///
    /// # Arguments
    ///
    /// `option` - A `u8` representing the telnet option code that you want to disable locally.
    ///
    /// # Returns
    ///
    /// `Option<TelnetEvents::DataSend>` - A `DataSend` event to be processed, or None if the option is already disabled.
    ///
    pub fn _wont(&mut self, option: u8) -> Option<Event> {
        let opt = self.options.option_mut(option);
        if !opt.local_enabled() {
            return None;
        }
        opt.clear_local_enabled();
        Some(self.negotiate(WONT, option))
    }

    /// Indicate to the other side that you would like them to utilize an option.
    ///
    /// # Arguments
    ///
    /// `option` - A `u8` representing the telnet option code that you want to enable remotely.
    ///
    /// # Returns
    ///
    /// `Option<TelnetEvents::DataSend>` - A `DataSend` event to be processed, or None if the option is not supported or already enabled.
    ///
    /// # Notes
    ///
    /// This method will do nothing if the option is not "supported" remotely via the `CompatibilityTable`.
    pub fn _do(&mut self, option: u8) -> Option<Event> {
        let opt = self.options.option_mut(option);
        if !opt.remote_support() || opt.remote_enabled() {
            return None;
        }
        opt.set_remote_enabled();
        Some(self.negotiate(DO, option))
    }

    /// Indicate to the other side that you would like them to stop utilizing an option.
    ///
    /// # Arguments
    ///
    /// `option` - A `u8` representing the telnet option code that you want to disable remotely.
    ///
    /// # Returns
    ///
    /// `Option<TelnetEvents::DataSend>` - A `DataSend` event to be processed, or None if the option is already disabled.
    ///
    pub fn _dont(&mut self, option: u8) -> Option<Event> {
        if !self.options.option(option).remote_enabled() {
            return None;
        }
        Some(self.negotiate(DONT, option))
    }

    /// Send a subnegotiation for a locally supported option.
    ///
    /// # Arguments
    ///
    /// `option` - A `u8` representing the telnet option code for the negotiation.
    ///
    /// `data` - A `Bytes` containing the data to be sent in the subnegotiation. This data will have all IAC (255) byte values escaped.
    ///
    /// # Returns
    ///
    /// `Option<TelnetEvents::DataSend>` - A `DataSend` event to be processed, or None if the option is not supported or is currently disabled.
    ///
    /// # Notes
    ///
    /// This method will do nothing if the option is not "supported" locally via the `CompatibilityTable`.
    pub fn subnegotiation<T>(&mut self, option: u8, data: T) -> Option<Event>
    where
        Bytes: From<T>,
    {
        let opt = self.options.option(option);
        if !opt.local_support() || !opt.local_enabled() {
            return None;
        }
        Some(Event::DataSend(
            Subnegotiation {
                option,
                buffer: Bytes::from(data),
            }
            .into(),
        ))
    }

    /// Send a subnegotiation for a locally supported option, using a string instead of raw byte values.
    ///
    /// # Arguments
    ///
    /// `option` - A `u8` representing the telnet option code for the negotiation.
    ///
    /// `text` - A `&str` representing the text to be sent in the subnegotation. This data will have all IAC (255) byte values escaped.
    ///
    /// # Returns
    ///
    /// `Option<TelnetEvents::DataSend>` - A `DataSend` event to be processed, or None if the option is not supported or is currently disabled.
    ///
    /// # Notes
    ///
    /// This method will do nothing if the option is not "supported" locally via the `CompatibilityTable`.
    pub fn subnegotiation_text(&mut self, option: u8, text: &str) -> Option<Event> {
        self.subnegotiation(option, Bytes::copy_from_slice(text.as_bytes()))
    }

    /// Directly send a string, with appended `\r\n`, to the remote end, along with an `IAC (255) GOAHEAD (249)` sequence.
    ///
    /// # Returns
    ///
    /// `TelnetEvents::DataSend` - A `DataSend` event to be processed.
    ///
    /// # Notes
    ///
    /// The string will have IAC (255) bytes escaped before being sent.
    pub fn send_text(&mut self, text: &str) -> Event {
        Event::DataSend(Parser::escape_iac(format!("{text}\r\n")))
    }

    #[must_use]
    pub fn flush_line(&mut self) -> Option<Bytes> {
        if self.line_buffer.is_empty() {
            None
        } else {
            Some(self.line_buffer.split().freeze())
        }
    }

    /// The internal parser method that takes the current buffer and generates the corresponding events.
    fn process(&mut self) -> Vec<Event> {
        let mut event_list = Vec::with_capacity(2);
        let events = self.extract_event_data();
        for event in events {
            match event {
                EventType::None(buffer) | EventType::Iac(buffer) | EventType::Neg(buffer) => {
                    match (buffer.first(), buffer.get(1), buffer.get(2)) {
                        (Some(&IAC), Some(command), None) if *command != SE => {
                            // IAC command
                            event_list.push(Event::Iac(Iac { command: *command }));
                        }
                        (Some(&IAC), Some(command), Some(opt)) => {
                            // Negotiation command
                            event_list.extend(self.process_negotiation(*command, *opt));
                        }
                        (Some(c), _, _) if *c != IAC => {
                            self.line_buffer.extend_from_slice(&buffer);
                            // Not an iac sequence, it's data!
                            if self.deframe_lines {
                                event_list.extend(self.deframe_lines());
                            } else {
                                event_list.push(Event::DataReceive(buffer));
                            }
                        }
                        _ => {}
                    }
                }
                EventType::SubNegotiation(buffer, remaining) => {
                    let len = buffer.len();
                    if buffer[len - 2] == IAC && buffer[len - 1] == SE {
                        // Valid ending
                        let opt = self.options.option(buffer[2]);
                        if opt.local_support() && opt.local_enabled() && len - 2 >= 3 {
                            event_list.push(Event::Subnegotiation(Subnegotiation {
                                option: buffer[2],
                                buffer: Bytes::copy_from_slice(&buffer[3..len - 2]),
                            }));
                            if let Some(rbuf) = remaining {
                                event_list.push(Event::DecompressImmediate(rbuf));
                            }
                        }
                    } else {
                        // Missing the rest
                        self.buffer.put(&buffer[..]);
                    }
                }
            }
        }
        event_list
    }

    fn process_negotiation(&mut self, command: u8, option: u8) -> Vec<Event> {
        let event = Negotiation { command, option };
        match (command, self.options.option_mut(option)) {
            (WILL, entry) if entry.remote_support() && !entry.remote_enabled() => {
                entry.set_remote_enabled();
                vec![
                    Event::DataSend(Bytes::copy_from_slice(&[IAC, DO, option])),
                    Event::Negotiation(event),
                ]
            }
            (WILL, entry) if !entry.remote_support() => {
                vec![Event::DataSend(Bytes::copy_from_slice(&[
                    IAC, DONT, option,
                ]))]
            }
            (WONT, entry) if entry.remote_enabled() => {
                entry.clear_remote_enabled();
                vec![
                    Event::DataSend(Bytes::copy_from_slice(&[IAC, DONT, option])),
                    Event::Negotiation(event),
                ]
            }
            (DO, entry) if entry.local_support() && !entry.local_enabled() => {
                entry.set_local_enabled();
                entry.set_remote_enabled();
                vec![
                    Event::DataSend(Bytes::copy_from_slice(&[IAC, WILL, option])),
                    Event::Negotiation(event),
                ]
            }
            (DO, entry) if !entry.local_support() || !entry.local_enabled() => {
                vec![Event::DataSend(Bytes::copy_from_slice(&[
                    IAC, WONT, option,
                ]))]
            }
            (DONT, entry) if entry.local_enabled() => {
                entry.clear_local_enabled();
                vec![
                    Event::DataSend(Bytes::copy_from_slice(&[IAC, WONT, option])),
                    Event::Negotiation(event),
                ]
            }
            (DONT | WONT, Entry { .. }) => {
                vec![Event::Negotiation(event)]
            }
            _ => Vec::default(),
        }
    }

    /// Extract sub-buffers from the current buffer
    fn extract_event_data(&mut self) -> Vec<EventType> {
        #[derive(Copy, Clone)]
        enum State {
            Normal,
            Iac,
            Neg,
            Sub,
            SubOpt { opt: u8 },
            SubIac { opt: u8 },
        }

        let mut events = Vec::with_capacity(4);
        let mut iter_state = State::Normal;
        let mut cmd_begin = 0;

        // Empty self.buffer into an immutable Bytes we can process.
        // We'll create views of this buffer to pass to the events using 'buf.slice'.
        // Splitting is O(1) and doesn't copy the data. Freezing is zero-cost. Taking a slice is O(1).
        let buf = self.buffer.split().freeze();
        for (index, &val) in buf.iter().enumerate() {
            (iter_state, cmd_begin) = match (&iter_state, val) {
                (State::Normal, IAC) => {
                    if cmd_begin != index {
                        events.push(EventType::None(buf.slice(cmd_begin..index)));
                    }
                    (State::Iac, index)
                }
                (State::Iac, IAC) => (State::Normal, cmd_begin), // Double IAC, ignore,
                (State::Iac, GA | EOR | NOP) => {
                    events.push(EventType::Iac(buf.slice(cmd_begin..=index)));
                    (State::Normal, index + 1)
                }
                (State::Iac, SB) => (State::Sub, cmd_begin),
                (State::Iac, _) => (State::Neg, cmd_begin), // WILL | WONT | DO | DONT | IS | SEND
                (State::Neg, _) => {
                    events.push(EventType::Neg(buf.slice(cmd_begin..=index)));
                    (State::Normal, index + 1)
                }
                (State::Sub, opt) => (State::SubOpt { opt }, cmd_begin),
                (State::SubOpt { opt } | State::SubIac { opt }, IAC) => {
                    (State::SubIac { opt: *opt }, cmd_begin)
                }
                (State::SubIac { opt }, SE)
                    if *opt == telnet::op_option::MCCP2 || *opt == telnet::op_option::MCCP3 =>
                {
                    // MCCP2/MCCP3 MUST DECOMPRESS DATA AFTER THIS!
                    events.push(EventType::SubNegotiation(
                        buf.slice(cmd_begin..=index),
                        Some(buf.slice(index + 1..)),
                    ));
                    cmd_begin = buf.len();
                    break;
                }
                (State::SubIac { .. }, SE) => {
                    events.push(EventType::SubNegotiation(
                        buf.slice(cmd_begin..=index),
                        None,
                    ));
                    (State::Normal, index + 1)
                }
                (State::SubIac { opt }, _) => (State::SubOpt { opt: *opt }, cmd_begin),
                (cur_state, _) => (*cur_state, cmd_begin),
            };
        }

        if cmd_begin < buf.len() {
            match iter_state {
                State::Sub | State::SubOpt { .. } | State::SubIac { .. } => {
                    events.push(EventType::SubNegotiation(buf.slice(cmd_begin..), None));
                }
                _ => events.push(EventType::None(buf.slice(cmd_begin..))),
            }
        }

        events
    }

    fn deframe_lines(&mut self) -> Vec<Event> {
        const EOL: &[u8] = b"\r\n";
        const REVERSE_EOL: &[u8] = b"\n\r"; // For compat w/ Aardwolf (Blightmud@11e78c3).

        let mut events = Vec::new();

        // Note: this deframer logic is _very_ permissive. We intentionally allow deframing lines
        // delimited with:
        //  - \r\n (proper telnet EOL)
        //  - \n\r (lol - compat for Aardwolf (Blightmud@11e78c3)).
        // We may need to consider allowing just '\n'.
        while let Some(line_end) = self
            .line_buffer
            .windows(2)
            .position(|bytes| bytes == EOL || bytes == REVERSE_EOL)
        {
            // Split the BytesMut buffer at the line end index - self.buf keeps the
            // content after the line_end index, the parts before are moved into a Line
            // as a frozen Bytes.
            // All of this is O(1) and should not allocate.
            events.push(Event::LineReceive(
                self.line_buffer.split_to(line_end).freeze(),
            ));
            // Consume the line ending we left behind after splitting the line.
            self.line_buffer.advance(2);
        }

        events
    }
}

#[cfg(feature = "tokio-util")]
impl Decoder for Parser {
    // TODO(XXX): ideally we would yield one Event at a time, but this is the smallest lift
    //   to adapt the existing library code.
    type Item = Vec<Event>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        let events = self.receive(src.split_off(0).as_ref());
        Ok(if events.is_empty() {
            None
        } else {
            Some(events)
        })
    }
}
