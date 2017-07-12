#!/usr/bin/env python3
import sys

def generate_lookup_table(name, func, n=256, align=16):
    assert(isinstance(n, int))
    FIRST_LINE = 'static {}: [bool; {}] = byte_map!['.format(name, n)
    LAST_LINE = '];'
    print(FIRST_LINE, end='')
    for i in range(n):
        if i % align == 0: print('\n   ', end='')
        print(' {},'.format(1 if func(i) else 0), end='')
    print('\n' + LAST_LINE + '\n')



def is_alphanum(b):
    return (ord(b'a') <= b <= ord(b'z')) or \
        (ord(b'A') <= b <= ord(b'Z')) or \
        (ord(b'0') <= b <= ord(b'9'))


''' RFC 3261
token       =  1*(alphanum / "-" / "." / "!" / "%" / "*"
                     / "_" / "+" / "`" / "'" / "~" )
'''
def is_token(b):
    return is_alphanum(b) or \
        (b in b"!%'*+-._`~")



''' RFC 3261
Request-URI    =  SIP-URI / SIPS-URI / absoluteURI
absoluteURI    =  scheme ":" ( hier-part / opaque-part )
hier-part      =  ( net-path / abs-path ) [ "?" query ]
net-path       =  "//" authority [ abs-path ]
abs-path       =  "/" path-segments
SIP-URI          =  "sip:" [ userinfo ] hostport
                    uri-parameters [ headers ]
SIPS-URI         =  "sips:" [ userinfo ] hostport
                    uri-parameters [ headers ]
userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
user             =  1*( unreserved / escaped / user-unreserved )
user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
password         =  *( unreserved / escaped /
                    "&" / "=" / "+" / "$" / "," )
hostport         =  host [ ":" port ]
host             =  hostname / IPv4address / IPv6reference
hostname         =  *( domainlabel "." ) toplabel [ "." ]
domainlabel      =  alphanum
                    / alphanum *( alphanum / "-" ) alphanum
toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
'''
def is_request_uri(b):
    return is_alphanum(b) or \
        (b in b"!$%&'()*+,-./:;=?@_~")


''' RFC 3261
Reason-Phrase   =  *(reserved / unreserved / escaped
                   / UTF8-NONASCII / UTF8-CONT / SP / HTAB)
'''
def is_reason_phrase(b):
    return is_alphanum(b) or \
        (b in b"!$%&'()*+,-./:;=?@_~") or \
        (b in b"\xff") or \
        (b in b" \t")


'''
TEXT-UTF8char   =  %x21-7E / UTF8-NONASCII
'''
def is_TEXT_UTF8char(b):
    return (ord(b'\x21') <= b <= ord(b'\x7E')) or \
        is_UTF8_NONASCII(b)

'''
UTF8-NONASCII   =  %xC0-DF 1UTF8-CONT
                /  %xE0-EF 2UTF8-CONT
                /  %xF0-F7 3UTF8-CONT
                /  %xF8-Fb 4UTF8-CONT
                /  %xFC-FD 5UTF8-CONT
'''
def is_UTF8_NONASCII(b):
    return (ord(b'\xC0') <= b <= ord(b'\xDF')) or \
        (ord(b'\xE0') <= b <= ord(b'\xEF')) or \
        (ord(b'\xF0') <= b <= ord(b'\xF7')) or \
        (ord(b'\xF8') <= b <= ord(b'\xFb')) or \
        (ord(b'\xFC') <= b <= ord(b'\xFD'))

'''
UTF8-CONT       =  %x80-BF
'''
def is_UTF8_CONT(b):
    return (ord(b'\x80') <= b <= ord(b'\xBF'))

'''
Where ([THIS](https://www.rfc-editor.org/std/std68.txt)):

LWS  =  [*WSP CRLF] 1*WSP ; linear whitespace
WSP     =  SP / HTAB          ; white space
SP      =  %x20               ; space
HTAB    =  %x09               ; horizontal tab
'''
def is_LWS(b):
    return (b in b'\x20\x09\r\n')

'''
header-value      =  *(TEXT-UTF8char / UTF8-CONT / LWS)
'''
def is_header_value(b):
    return is_TEXT_UTF8char(b) or \
        is_UTF8_CONT(b) or \
        is_LWS(b) or \
        (b in b'\x00\x07\x7F') # NUL BEL DEL - not sure if valid


GENERATORS = {
    'TOKEN_MAP': is_token,
    'REQUEST_URI_MAP': is_request_uri,
    'REASON_PHRASE_MAP': is_reason_phrase,
    'HEADER_VALUE_MAP': is_header_value,
}

def main(args):
    for arg in args:
        func = GENERATORS[arg]
        generate_lookup_table(arg, func)

main(sys.argv[1:])
