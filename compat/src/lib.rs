use libmudtelnet::compatibility::{Entry, Table};
use libmudtelnet::events::{Event, Iac, Negotiation, Subnegotiation};
use libmudtelnet::Parser;

use libtelnet_rs::compatibility::CompatibilityTable as OgCompatibilityTable;
use libtelnet_rs::events::TelnetEvents as OgTelnetEvents;
use libtelnet_rs::Parser as OgParser;

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TelnetApplication {
    pub options: Vec<(u8, u8)>,
    pub received_data: Vec<Vec<u8>>,
}

pub fn test_app(app: &TelnetApplication) {
    let mut parser = Parser::with_support(Table::from_options(&app.options));
    let mut og_parser = OgParser::with_support(OgCompatibilityTable::from_options(&app.options));

    for data in &app.received_data {
        let our_events = parser.receive(&data);
        let og_events = events(og_parser.receive(&data));
        assert_eq!(our_events, og_events);
    }

    for opt in 0..255 {
        let our_opt_state = *parser.options.option(opt);
        let og_opt_state = og_parser.options.get_option(opt);
        assert_eq!(
            <Entry as Into<u8>>::into(our_opt_state),
            og_opt_state.into_u8()
        );
    }
}

pub fn events(events: Vec<OgTelnetEvents>) -> Vec<Event> {
    events.into_iter().map(event).collect()
}

pub fn event(event: OgTelnetEvents) -> Event {
    match event {
        OgTelnetEvents::IAC(iac) => Event::Iac(Iac {
            command: iac.command,
        }),
        OgTelnetEvents::Negotiation(neg) => Event::Negotiation(Negotiation {
            command: neg.command,
            option: neg.option,
        }),
        OgTelnetEvents::Subnegotiation(sub) => Event::Subnegotiation(Subnegotiation {
            option: sub.option,
            buffer: sub.buffer,
        }),
        OgTelnetEvents::DataReceive(data) => Event::DataReceive(data),
        OgTelnetEvents::DataSend(data) => Event::DataSend(data),
        OgTelnetEvents::DecompressImmediate(data) => Event::DecompressImmediate(data),
    }
}

pub fn test_escape(data: Vec<u8>) {
    // For any input if we escape it, and then unescape it, we should get back the original data.
    let escaped = Parser::escape_iac(data.clone());
    let unescaped = Parser::unescape_iac(escaped.clone());
    assert_eq!(data, unescaped);

    // The same should be true for the original implementation.
    let og_escaped = OgParser::escape_iac(data.clone());
    let og_unescaped = OgParser::unescape_iac(og_escaped.clone());
    assert_eq!(data, og_unescaped);

    // And we expect the new and old implementation produce the same escaped output.
    assert_eq!(escaped, og_escaped);
}
