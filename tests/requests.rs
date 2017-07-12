extern crate parsip;

use parsip::{IResult, Request, Header, EMPTY_HEADER, SipVersion};

const NUM_OF_HEADERS: usize = 32;

macro_rules! req {
    ($name:ident, $buf:expr, |$arg:ident| $body:expr) => (
        req! {$name, $buf, |buf| IResult::Done(&buf[buf.len()..], buf.len()), |$arg| $body }
    );
    ($name:ident, $buf:expr, |$res_arg:ident| $res_body:expr, |$arg:ident| $body:expr) => (
    #[test]
    fn $name() {
        let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
        let mut req = Request::new(&mut headers[..]);
        let result = req.parse($buf.as_ref());
        assert_eq!(result, res_closure($buf));
        closure(req);

        fn res_closure($res_arg: &[u8]) -> IResult<&[u8], usize> {
            $res_body
        }

        fn closure($arg: Request) {
            $body
        }
    }
    )
}

/// Helper for debugging
fn print_headers(headers: &[Header]) {
    for header in headers.iter() {
        println!("Header {{ name: {:?}, value: {:?} }}",
                 header.name,
                 std::str::from_utf8(header.value).unwrap());
    }
}

/// From [RFC 4475](https://tools.ietf.org/html/rfc4475#section-3.1.1.1):
/// 3.1.1.  Valid Messages
/// 3.1.1.1.  A Short Tortuous INVITE
req! {
    test_request_short_tortuous_invite,
    include_bytes!("requests/wsinv.dat"),
    |buf| IResult::Done(&buf[857..], 857),
    |req| {
        assert_eq!(req.method.unwrap(), "INVITE");
        assert_eq!(req.path.unwrap(), "sip:vivekg@chair-dnrc.example.com;unknownparam");
        assert_eq!(req.version.unwrap(), SipVersion(2,0));
        assert_eq!(req.headers.len(), 14);
        print_headers(req.headers);
    }
}

/// From [RFC 4475](https://tools.ietf.org/html/rfc4475#section-3.1.1.2):
/// 3.1.1.  Valid Messages
/// 3.1.1.2.  Wide Range of Valid Characters
req! {
    test_request_wide_range_of_valid_characters,
    include_bytes!("requests/intmeth.dat"),
    |buf| IResult::Done(&buf[681..], 681),
    |req| {
        assert_eq!(req.method.unwrap(), "!interesting-Method0123456789_*+`.%indeed\'~");
        assert_eq!(req.path.unwrap(),
            "sip:1_unusual.URI~(to-be!sure)&isn\'t+it$/crazy?,/;;*:&it+has=1,\
            weird!*pas$wo~d_too.(doesn\'t-it)@example.com");
        assert_eq!(req.version.unwrap(), SipVersion(2,0));
        assert_eq!(req.headers.len(), 8);
        print_headers(req.headers);
    }
}

/// From [RFC 4475](https://tools.ietf.org/html/rfc4475#section-3.1.1.3):
/// 3.1.1.  Valid Messages
/// 3.1.1.3.  Valid Use of the % Escaping Mechanism
req! {
    test_request_valid_use_of_the_percent_escaping_mechanism,
    include_bytes!("requests/esc01.dat"),
    |buf| IResult::Done(&buf[409..], 409),
    |req| {
        assert_eq!(req.method.unwrap(), "INVITE");
        assert_eq!(req.path.unwrap(), "sip:sips%3Auser%40example.com@example.net");
        assert_eq!(req.version.unwrap(), SipVersion(2,0));
        assert_eq!(req.headers.len(), 9);
        print_headers(req.headers);
    }
}

/// From [RFC 4475](https://tools.ietf.org/html/rfc4475#section-3.1.1.4):
/// 3.1.1.  Valid Messages
/// 3.1.1.4.  Escaped Nulls in URIs
req! {
    test_request_escaped_nulls_in_uris,
    include_bytes!("requests/escnull.dat"),
    |buf| IResult::Done(&buf[365..], 365),
    |req| {
        assert_eq!(req.method.unwrap(), "REGISTER");
        assert_eq!(req.path.unwrap(), "sip:example.com");
        assert_eq!(req.version.unwrap(), SipVersion(2,0));
        assert_eq!(req.headers.len(), 9);
        print_headers(req.headers);
    }
}

/// From [RFC 4475](https://tools.ietf.org/html/rfc4475#section-3.1.1.5):
/// 3.1.1.  Valid Messages
/// 3.1.1.5.  Use of % When It Is Not an Escape
req! {
    test_request_use_of_percent_when_it_is_not_an_escape,
    include_bytes!("requests/esc02.dat"),
    |buf| IResult::Done(&buf[445..], 445),
    |req| {
        assert_eq!(req.method.unwrap(), "RE%47IST%45R");
        assert_eq!(req.path.unwrap(), "sip:registrar.example.com");
        assert_eq!(req.version.unwrap(), SipVersion(2,0));
        assert_eq!(req.headers.len(), 10);
        print_headers(req.headers);
    }
}
