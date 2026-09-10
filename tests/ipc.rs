//! Wire framing round-trip over an in-memory buffer -- no socket, no
//! running daemon needed, since `protocol::{read,write}_message` are
//! generic over `Read`/`Write` rather than tied to `UnixStream`.

use mitos_network::ipc::messages::{Request, Response, ServerMessage};
use mitos_network::ipc::protocol::{read_message, write_message};
use std::io::Cursor;

#[test]
fn request_round_trips_through_the_wire_format() {
    let req = Request::ActivateConnection {
        id: "home-wifi".to_string(),
    };
    let mut buf = Vec::new();
    write_message(&mut buf, &req).unwrap();

    let mut cursor = Cursor::new(buf);
    let decoded: Request = read_message(&mut cursor).unwrap();
    match decoded {
        Request::ActivateConnection { id } => assert_eq!(id, "home-wifi"),
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn multiple_messages_can_be_framed_back_to_back() {
    let mut buf = Vec::new();
    write_message(&mut buf, &ServerMessage::Response(Response::Ok)).unwrap();
    write_message(
        &mut buf,
        &ServerMessage::Response(Response::Error("boom".to_string())),
    )
    .unwrap();

    let mut cursor = Cursor::new(buf);
    let first: ServerMessage = read_message(&mut cursor).unwrap();
    let second: ServerMessage = read_message(&mut cursor).unwrap();

    assert!(matches!(first, ServerMessage::Response(Response::Ok)));
    match second {
        ServerMessage::Response(Response::Error(msg)) => assert_eq!(msg, "boom"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn truncated_stream_is_an_error_not_a_panic() {
    let mut buf = Vec::new();
    write_message(&mut buf, &Request::GetState).unwrap();
    buf.truncate(buf.len() - 2); // cut the message body short
    let mut cursor = Cursor::new(buf);
    let result: mitos_network::errors::Result<Request> = read_message(&mut cursor);
    assert!(result.is_err());
}
