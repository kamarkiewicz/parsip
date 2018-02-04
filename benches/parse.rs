#[macro_use]
extern crate bencher;

use bencher::Bencher;

extern crate parsip;

const REQ: &'static [u8] = b"\
INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8;received=192.0.2.1\r\n\
Max-Forwards: 69\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\r\n";



fn bench_parsip_request(b: &mut Bencher) {
    let mut headers = [parsip::Header {
        name: "",
        value: &[],
    }; 16];
    let mut req = parsip::Request::new(&mut headers);
    b.iter(|| {
               assert_eq!(req.parse(REQ), parsip::IResult::Done(&b""[..], REQ.len()));
           });
    b.bytes = REQ.len() as u64;
}

benchmark_group!(benches, bench_parsip_request);
benchmark_main!(benches);
