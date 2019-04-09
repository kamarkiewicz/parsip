use nom::{digit, is_space, line_ending, crlf, rest};
use std::{str, slice};
use lookup::{is_token, is_request_uri, is_reason_phrase, is_header_value};

/// A Result of any parsing action.
///
/// If the input is invalid, an `IResult::Error` will be returned.
/// Note that incomplete data is not considered invalid,
/// and so will not return an error, but rather a `IResult::Incomplete(_)`.
pub use nom::{IResult, Err, ErrorKind, Needed};

#[inline]
fn shrink<T>(slice: &mut &mut [T], len: usize) {
    debug_assert!(slice.len() >= len);
    let ptr = slice.as_mut_ptr();
    *slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
}

/// An error in parsing.
/// TODO: for now this is unused; use this custom error type
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Invalid byte in header name.
    HeaderName,
    /// Invalid byte in header value.
    HeaderValue,
    /// Invalid byte in new line.
    NewLine,
    /// Invalid byte in Response status.
    Status,
    /// Invalid byte where token is required.
    Token,
    /// Parsed more headers than provided buffer can contain.
    TooManyHeaders,
    /// Invalid byte in SIP version.
    Version,
}

/// A parsed Request.
///
/// The optional values will be `None` if a parse was not complete, and did not
/// parse the associated property. This allows you to inspect the parts that
/// could be parsed, before reading more, in case you wish to exit early.
///
/// # Example
///
/// ```
/// let buf = b"INVITE sip:callee@domain.com SIP/2.0\r\nHost:";
/// let mut headers = [parsip::EMPTY_HEADER; 16];
/// let mut req = parsip::Request::new(&mut headers);
/// let res = req.parse(buf);
/// if let parsip::IResult::Incomplete(_) = res {
///     match req.path {
///         Some(ref path) => {
///             // check router for path.
///             // is domain.com unreachable? we could stop parsing
///         },
///         None => {
///             // must read more and parse again
///         }
///     }
/// }
/// ```
#[derive(Debug, PartialEq)]
pub struct Request<'headers, 'buf: 'headers> {
    /// The request method, such as `INVITE`.
    pub method: Option<&'buf str>,
    /// The request path, such as `sip:callee@domain.com`.
    pub path: Option<&'buf str>,
    /// The request version, such as `SIP/2.0`.
    pub version: Option<SipVersion>,
    /// The request headers.
    pub headers: &'headers mut [Header<'buf>],
}

impl<'h, 'b> Request<'h, 'b> {
    /// Creates a new Request, using a slice of headers you allocate.
    #[inline]
    pub fn new(headers: &'h mut [Header<'b>]) -> Request<'h, 'b> {
        Request {
            method: None,
            path: None,
            version: None,
            headers: headers,
        }
    }

    /// > ```notrust
    /// > Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
    /// > ```
    // TODO: extract parse_request_line method when figure out how
    pub fn parse(&mut self, buf: &'b [u8]) -> IResult<&'b [u8], usize> {
        do_parse!(buf,
            begin: rest_len >>
            skip_empty_lines >>
            map!(parse_method, |method| self.method = Some(method)) >> char!(' ') >>
            map!(parse_request_uri, |path| self.path = Some(path)) >> char!(' ') >>
            map!(parse_version, |version| self.version = Some(version)) >> crlf >>
            headers_len: map!(call!(parse_headers, self.headers), |headers| headers.len()) >>
            crlf >>
            end: rest_len >>
            ({
                shrink(&mut self.headers, headers_len);
                begin - end
            })
        )
    }
}

/// Helper that results in number of remaining bytes
named!(#[inline], rest_len<usize>, map!(peek!(rest), |buf| buf.len()));

/// Helper that skips all `\r\n` or `\n` bytes
named!(#[inline], skip_empty_lines<()>,
    fold_many0!(line_ending, (), |_, _| ())
);

/// A parsed Response.
///
/// See `Request` docs for explanation of optional values.
#[derive(Debug, PartialEq)]
pub struct Response<'headers, 'buf: 'headers> {
    /// The response version, such as `SIP/2.0`.
    pub version: Option<SipVersion>,
    /// The response code, such as `200`.
    pub code: Option<u16>,
    /// The response reason-phrase, such as `OK`.
    pub reason: Option<&'buf str>,
    /// The response headers.
    pub headers: &'headers mut [Header<'buf>],
}

impl<'h, 'b> Response<'h, 'b> {
    /// Creates a new `Response` using a slice of `Header`s you have allocated.
    #[inline]
    pub fn new(headers: &'h mut [Header<'b>]) -> Response<'h, 'b> {
        Response {
            version: None,
            code: None,
            reason: None,
            headers: headers,
        }
    }

    /// Try to parse a buffer of bytes into this `Response`.
    ///
    /// > ```notrust
    /// > Status-Line     =  SIP-Version SP Status-Code SP Reason-Phrase CRLF
    /// > ```
    // TODO: extract parse_status_line method when figure out how
    pub fn parse(&mut self, buf: &'b [u8]) -> IResult<&'b [u8], usize> {
        do_parse!(buf,
            begin: rest_len >>
            skip_empty_lines >>
            map!(parse_version, |version| self.version = Some(version)) >> char!(' ') >>
            map!(parse_code, |code| self.code = Some(code)) >> char!(' ') >>
            map!(parse_reason, |reason| self.reason = Some(reason)) >> crlf >>
            headers_len: map!(call!(parse_headers, self.headers), |headers| headers.len()) >>
            crlf >>
            end: rest_len >>
            ({
                shrink(&mut self.headers, headers_len);
                begin - end
            })
        )
    }
}

/// Represents a parsed header.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Header<'a> {
    /// The name portion of a header.
    ///
    /// A header name must be valid US-ASCII, so it's safe to store as a `&str`.
    pub name: &'a str,
    /// The value portion of a header.
    ///
    /// While headers **should** be US-ASCII, the specification allows for
    /// values that may not be, and so the value is stored as bytes.
    pub value: &'a [u8],
}

/// An empty header, useful for constructing a `Header` array to pass in for
/// parsing.
///
/// # Example
///
/// ```
///# #![allow(unused_variables)]
/// let headers = [parsip::EMPTY_HEADER; 64];
/// ```
pub const EMPTY_HEADER: Header<'static> = Header {
    name: "",
    value: b"",
};

/// SIP-Version
/// ex. `SIP/2.0 -> SipVersion(2, 0)`
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct SipVersion(pub u8, pub u8);

/// Get one digit from input and return it as `u8` (ie. `b'7'` becomes `7`)
named!(#[inline], single_digit<&[u8], u8>,
    map!(
        flat_map!(take!(1), digit),
        |a| a[0] - b'0'
    )
);

/// Eats token bytes
named!(#[inline], parse_token<&[u8], &str>,
    map_res!(take_while1!(is_token), str::from_utf8)
);

/// > ```notrust
/// > Method            =  INVITEm / ACKm / OPTIONSm / BYEm
/// >                      / CANCELm / REGISTERm
/// >                      / extension-method
/// > extension-method  =  token
/// > ```
named!(#[inline], parse_method<&[u8], &str>,
    call!(parse_token)
);

/// As parsing uri is a bit complicated, it should be properly
/// parsed in higher layers of parsing.
///
/// > ```notrust
/// > Request-URI    =  SIP-URI / SIPS-URI / absoluteURI
/// > absoluteURI    =  scheme ":" ( hier-part / opaque-part )
/// > hier-part      =  ( net-path / abs-path ) [ "?" query ]
/// > net-path       =  "//" authority [ abs-path ]
/// > abs-path       =  "/" path-segments
/// > SIP-URI          =  "sip:" [ userinfo ] hostport
/// >                     uri-parameters [ headers ]
/// > SIPS-URI         =  "sips:" [ userinfo ] hostport
/// >                     uri-parameters [ headers ]
/// > userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
/// > user             =  1*( unreserved / escaped / user-unreserved )
/// > user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
/// > password         =  *( unreserved / escaped /
/// >                     "&" / "=" / "+" / "$" / "," )
/// > hostport         =  host [ ":" port ]
/// > host             =  hostname / IPv4address / IPv6reference
/// > hostname         =  *( domainlabel "." ) toplabel [ "." ]
/// > domainlabel      =  alphanum
/// >                     / alphanum *( alphanum / "-" ) alphanum
/// > toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
/// > ```
named!(#[inline], parse_request_uri<&[u8], &str>,
    map_res!(take_while1!(is_request_uri), str::from_utf8)
);

/// From [RFC 3261](https://tools.ietf.org/html/rfc3261#section-7.1):
///
/// The SIP-Version string is case-insensitive,
/// but implementations MUST send upper-case.
///
/// > ```notrust
/// > SIP-Version    =  "SIP" "/" 1*DIGIT "." 1*DIGIT
/// > ```
named!(#[inline], parse_version<SipVersion>,
    do_parse!(
        tag_no_case!("SIP/") >>
        x: single_digit >>
        char!('.') >>
        y: single_digit >>
        ( SipVersion(x, y) )
    )
);

/// From [RFC 3261](https://tools.ietf.org/html/rfc3261):
///
/// > ```notrust
/// > Reason-Phrase   =  *(reserved / unreserved / escaped
/// >                    / UTF8-NONASCII / UTF8-CONT / SP / HTAB)
/// > ```
named!(#[inline], parse_reason<&[u8], &str>,
    map_res!(take_while!(is_reason_phrase), str::from_utf8)
);

// From [RFC 3261](https://tools.ietf.org/html/rfc3261):
///
/// > ```notrust
/// > Status-Code     =  Informational
/// >                /   Redirection
/// >                /   Success
/// >                /   Client-Error
/// >                /   Server-Error
/// >                /   Global-Failure
/// >                /   extension-code
/// > ```
named!(#[inline], parse_code<&[u8], u16>,
    map!(
        flat_map!(take!(3), digit),
        |arr| (arr[0] - b'0') as u16 * 100 + (arr[1] - b'0') as u16 * 10 +
              (arr[2] - b'0') as u16
    )
);

/// > ```notrust
/// > header-name       =  token
/// > ```
named!(#[inline], header_name<&[u8], &str>,
    map_res!(
        take_while!(is_token),
        str::from_utf8
    )
);

/// From [RFC 3261](https://tools.ietf.org/html/rfc3261#section-7.3.1):
///
/// Header fields can be extended over multiple lines by preceding each
/// extra line with at least one SP or horizontal tab (HT).
///
/// Header value may be empty!
///
fn header_value(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    use self::IResult::*;

    let mut end_pos = 0;
    let mut idx = 0;
    while idx < buf.len() {
        match buf[idx] {
            b'\n' => {
                idx += 1;
                if idx >= buf.len() {
                    return Incomplete(Needed::Size(1));
                }
                match buf[idx] {
                    b' ' | b'\t' => {
                        idx += 1;
                        continue;
                    }
                    _ => {
                        return Done(&buf[end_pos..], &buf[..end_pos]);
                    }
                }
            }
            b' ' | b'\t' | b'\r' => {}
            b => {
                if !is_header_value(b) {
                    return Error(error_position!(ErrorKind::Custom(b as u32), buf));
                }
                end_pos = idx + 1;
            }
        }
        idx += 1;
    }
    Done(&b""[..], buf)
}

/// > ```notrust
/// > HCOLON  =  *( SP / HTAB ) ":" SWS
/// > ```
named!(hcolon<char>, delimited!(
    take_while!(is_space),
    char!(':'),
    take_while!(is_space)
));

/// > ```notrust
/// > header  =  "header-name" HCOLON header-value *(COMMA header-value)
/// > ```
named!(message_header<Header>, do_parse!(
    n: header_name  >>
    hcolon >>
    v: header_value >>
    crlf >>
    (Header{ name: n, value: v })
));

/// Parse a buffer of bytes as headers.
///
/// The return value, if complete and successful, includes the index of the
/// buffer that parsing stopped at, and a sliced reference to the parsed
/// headers. The length of the slice will be equal to the number of properly
/// parsed headers.
///
/// # Example
///
/// ```
/// let buf = b"Host: foo.bar\r\nAccept: */*\r\n\r\n";
/// let mut headers = [parsip::EMPTY_HEADER; 4];
/// assert_eq!(parsip::parse_headers(buf, &mut headers),
///            parsip::IResult::Done(&buf[28..], &[
///                parsip::Header { name: "Host", value: b"foo.bar" },
///                parsip::Header { name: "Accept", value: b"*/*" }
///            ][..]));
/// ```
pub fn parse_headers<'b: 'h, 'h>(mut input: &'b [u8],
                                 mut headers: &'h mut [Header<'b>])
                                 -> IResult<&'b [u8], &'h [Header<'b>]> {
    use self::IResult::*;
    let mut i = 0;
    while i < headers.len() {
        match crlf(input) {
            Done(_, _) => break,
            Error(_) => {}
            Incomplete(e) => return Incomplete(e),
        };
        let (rest, header) = try_parse!(input, message_header);
        headers[i] = header;
        input = rest;
        i += 1;
    }

    shrink(&mut headers, i);
    Done(input, headers)
}


#[cfg(test)]
mod tests {
    use super::{IResult, ErrorKind, Needed};
    use super::{Request, Response, EMPTY_HEADER, SipVersion};

    const NUM_OF_HEADERS: usize = 4;

    macro_rules! req {
        ($name:ident, $buf:expr, |$arg:ident| $body:expr) => (
            req! {$name, $buf,
                 |buf| IResult::Done(&buf[buf.len()..], buf.len()),
                 |$arg| $body }
        );
        ($name:ident, $buf:expr,
         |$res_arg:ident| $res_body:expr,
         |$arg:ident| $body:expr) => (
        #[test]
        fn $name() {
            let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
            let mut req = Request::new(&mut headers);
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

    #[test]
    fn test_header_value_empty() {
        let buf = b"\r\nAccept: */*\r\n\r\n";
        assert_eq!(super::header_value(buf),
                   IResult::Done(&buf[0..], &buf[..0]));
    }

    req! {
        test_request_simple,
        b"INVITE sip:callee@domain.com SIP/2.0\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "INVITE");
            assert_eq!(req.path.unwrap(), "sip:callee@domain.com");
            assert_eq!(req.version.unwrap(), SipVersion(2,0));
            assert_eq!(req.headers.len(), 0);
        }
    }

    req! {
        test_request_headers,
        b"INVITE sip:callee@domain.com SIP/2.0\r\n\
          Host: foo.com\r\n\
          To: <sip:carol@chicago.com>\r\n\
          \r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "INVITE");
            assert_eq!(req.path.unwrap(), "sip:callee@domain.com");
            assert_eq!(req.version.unwrap(), SipVersion(2,0));
            assert_eq!(req.headers.len(), 2);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.com");
            assert_eq!(req.headers[1].name, "To");
            assert_eq!(req.headers[1].value, b"<sip:carol@chicago.com>");
        }
    }

    req! {
        test_request_headers_max,
        b"INVITE sip:callee@domain.com SIP/2.0\r\n\
          A: A\r\n\
          B: B\r\n\
          C: C\r\n\
          D: D\r\n\
          \r\n",
        |req| {
            assert_eq!(req.headers.len(), NUM_OF_HEADERS);
        }
    }

    req! {
        test_request_multibyte,
        b"INVITE sip:callee@domain.com SIP/2.0\r\nHost: foo.com\r\n\
        User-Agent: \xe3\x81\xb2\xe3/1.0\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "INVITE");
            assert_eq!(req.path.unwrap(), "sip:callee@domain.com");
            assert_eq!(req.version.unwrap(), SipVersion(2,0));
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.com");
            assert_eq!(req.headers[1].name, "User-Agent");
            assert_eq!(req.headers[1].value, b"\xe3\x81\xb2\xe3/1.0");
        }
    }

    req! {
        test_request_partial,
        b"INVITE sip:callee@domain.com SIP/2.0\r\n\r",
        |_buf| IResult::Incomplete(Needed::Size(40)),
        |_req| {}
    }

    req! {
        test_request_newlines,
        b"INVITE sip:callee@domain.com SIP/2.0\nHost: foo.bar\n\n",
        |_buf| IResult::Error(error_position!(ErrorKind::CrLf, &_buf[36..])),
        |_req| {}
    }

    req! {
        test_request_empty_lines_prefix,
        b"\r\n\r\nINVITE sip:callee@domain.com SIP/2.0\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "INVITE");
            assert_eq!(req.path.unwrap(), "sip:callee@domain.com");
            assert_eq!(req.version.unwrap(), SipVersion(2,0));
            assert_eq!(req.headers.len(), 0);
        }
    }

    req! {
        test_request_empty_lines_prefix_lf_only,
        b"\n\nINVITE sip:callee@domain.com SIP/2.0\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "INVITE");
            assert_eq!(req.path.unwrap(), "sip:callee@domain.com");
            assert_eq!(req.version.unwrap(), SipVersion(2,0));
        }
    }

    req! {
        test_request_with_invalid_token_delimiter,
        b"GET\n/ SIP/2.0\r\nHost: foo.bar\r\n\r\n",
        |_buf| IResult::Error(error_position!(ErrorKind::Char, &_buf[3..])),
        |_req| {}
    }

    req! {
        test_request_headers_with_continuation,
        b"INVITE sip:callee@domain.com SIP/2.0\r\n\
          NewFangledHeader:   newfangled value\r\n continued newfangled value\r\n\
          \r\n",
        |req| {
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "NewFangledHeader");
            assert_eq!(req.headers[0].value,
                &b"newfangled value\r\n continued newfangled value"[..]);
        }
    }

    macro_rules! res {
        ($name:ident, $buf:expr, |$arg:ident| $body:expr) => (
            res! {$name, $buf,
                 |buf| IResult::Done(&buf[buf.len()..], buf.len()),
                 |$arg| $body }
        );
        ($name:ident, $buf:expr,
         |$res_arg:ident| $res_body:expr,
         |$arg:ident| $body:expr) => (
        #[test]
        fn $name() {
            let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
            let mut res = Response::new(&mut headers);
            let result = res.parse($buf.as_ref());
            assert_eq!(result, res_closure($buf));
            closure(res);

            fn res_closure($res_arg: &[u8]) -> IResult<&[u8], usize> {
                $res_body
            }

            fn closure($arg: Response) {
                $body
            }
        }
        )
    }

    res! {
        test_response_simple,
        b"SIP/2.0 200 OK\r\n\r\n",
        |res| {
            assert_eq!(res.version.unwrap(), SipVersion(2,0));
            assert_eq!(res.code.unwrap(), 200);
            assert_eq!(res.reason.unwrap(), "OK");
        }
    }

    res! {
        test_response_newlines,
        b"SIP/2.0 403 Forbidden\nServer: foo.bar\n\n",
        |_buf| IResult::Error(error_position!(ErrorKind::CrLf, &_buf[21..])),
        |_res| {}
    }

    res! {
        test_response_reason_missing,
        b"SIP/2.0 200 \r\n\r\n",
        |res| {
            assert_eq!(res.version.unwrap(), SipVersion(2,0));
            assert_eq!(res.code.unwrap(), 200);
            assert_eq!(res.reason.unwrap(), "");
        }
    }

    res! {
        test_response_reason_missing_no_space,
        b"SIP/2.0 200\r\n\r\n",
        |_buf| IResult::Error(error_position!(ErrorKind::Char, &_buf[11..])),
        |res| {
            assert_eq!(res.version.unwrap(), SipVersion(2,0));
            assert_eq!(res.code.unwrap(), 200);
        }
    }

    res! {
        test_response_reason_with_space_and_tab,
        b"SIP/2.0 101 Switching Protocols\t\r\n\r\n",
        |res| {
            assert_eq!(res.version.unwrap(), SipVersion(2,0));
            assert_eq!(res.code.unwrap(), 101);
            assert_eq!(res.reason.unwrap(), "Switching Protocols\t");
        }
    }

    static RESPONSE_REASON_WITH_OBS_TEXT_BYTE: &'static [u8] = b"SIP/2.0 200 X\xFFZ\r\n\r\n";
    res! {
        test_response_reason_with_obsolete_text_byte,
        RESPONSE_REASON_WITH_OBS_TEXT_BYTE,
        |_buf| IResult::Error(error_position!(ErrorKind::MapRes, &_buf[12..])),
        |_res| {}
    }

    res! {
        test_response_reason_with_nul_byte,
        b"SIP/2.0 200 \x00\r\n\r\n",
        |_buf| IResult::Error(error_position!(ErrorKind::CrLf, &_buf[12..])),
        |_res| {}
    }

    res! {
        test_response_version_missing_space,
        b"SIP/2.0",
        |_buf| IResult::Incomplete(Needed::Size(8)),
        |_res| {}
    }

    res! {
        test_response_code_missing_space,
        b"SIP/2.0 200",
        |_buf| IResult::Incomplete(Needed::Size(12)),
        |_res| {}
    }

    res! {
        test_response_empty_lines_prefix_lf_only,
        b"\n\nSIP/2.0 200 OK\n\n",
        |_buf| IResult::Error(error_position!(ErrorKind::CrLf, &_buf[16..])),
        |_res| {}
    }
}
