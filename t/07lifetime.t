#vi:filetype=perl

# testcookie_lifetime: a signed cookie that carries its own expiry, and testcookie_previous_secret.
# The cookie stays 32 hex digits: 4 bytes of expiry (big-endian seconds) and the first 12 bytes of
# HMAC-SHA256(secret, expiry . session). Expected values are computed here, outside the module.

use lib 'lib';
use Test::Nginx::Socket;
use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(hmac_sha256);

our $S1 = 'flagmebla-flagmebla-flagmebla-flagmebla';
our $S2 = 'anothersecret-anothersecret-anothersecret';

sub signed {
    my ($expiry, $secret, $session) = @_;
    my $e = pack('N', $expiry);
    return unpack('H*', $e . substr(hmac_sha256($e . $session, $secret), 0, 12));
}

# any cookie the module may issue for 127.0.0.1 with a lifetime of 3600 s, from now on
sub issued_re {
    my $now = time();
    my $alt = join '|', map { signed($now + 3600 + $_, $S1, '127.0.0.1') } (-2 .. 30);
    return qr/^(?:$alt)$/;
}

plan tests => repeat_each(1) * 36;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: a signed cookie within its lifetime passes
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers eval
"Cookie: BPC=" . main::signed(time() + 60, $main::S1, '127.0.0.1')
--- error_code: 200
--- response_body_like: It works!

=== TEST 2: an expired cookie is challenged again
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers eval
"Cookie: BPC=" . main::signed(time() - 2, $main::S1, '127.0.0.1')
--- error_code: 307
--- response_headers_like
Set-Cookie: ^BPC=[0-9a-f]{32}; path=/; SameSite=None; Secure$

=== TEST 3: a moved expiry breaks the signature
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers eval
my $c = main::signed(time() - 2, $main::S1, '127.0.0.1');
"Cookie: BPC=" . sprintf('%08x', time() + 60) . substr($c, 8)
--- error_code: 307

=== TEST 4: one wrong digit of the signature
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers eval
my $c = main::signed(time() + 60, $main::S1, '127.0.0.1');
substr($c, 31, 1) = substr($c, 31, 1) eq '0' ? '1' : '0';
"Cookie: BPC=$c"
--- error_code: 307

=== TEST 5: a cookie signed for another session
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers eval
"Cookie: BPC=" . main::signed(time() + 60, $main::S1, '10.0.0.1')
--- error_code: 307

=== TEST 6: the old md5 cookie does not pass once the lifetime is on
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers
Cookie: BPC=87397509174b26fffd76bf2ab56b9b09
--- error_code: 307

=== TEST 7: the issued cookie is signed and expires after the lifetime
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template '$testcookie_set';
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- error_code: 200
--- response_body_like eval
main::issued_re()

=== TEST 8: the previous secret still passes, a signature by an unknown one does not
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_previous_secret anothersecret-anothersecret-anothersecret;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- request eval
["GET /", "GET /", "GET /"]
--- more_headers eval
["Cookie: BPC=" . main::signed(time() + 60, $main::S2, '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() + 60, $main::S1, '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() + 60, 'yetanothersecret-yetanothersecret-yet', '127.0.0.1')]
--- error_code eval
[200, 200, 307]

=== TEST 9: the previous secret is not taken without the directive
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers eval
"Cookie: BPC=" . main::signed(time() + 60, $main::S2, '127.0.0.1')
--- error_code: 307

=== TEST 10: the previous secret works for the old md5 cookie too
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_previous_secret anothersecret-anothersecret-anothersecret;
    testcookie_session $remote_addr;
--- config
    location / {
        testcookie on;
    }
--- request eval
["GET /", "GET /", "GET /"]
--- more_headers eval
["Cookie: BPC=" . main::md5_hex('127.0.0.1' . $main::S2),
 "Cookie: BPC=87397509174b26fffd76bf2ab56b9b09",
 "Cookie: BPC=" . main::md5_hex('127.0.0.1' . 'yetanothersecret-yetanothersecret-yet')]
--- error_code eval
[200, 200, 307]

=== TEST 11: testcookie_lifetime off in a location brings back the old cookie there
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location /old/ {
        testcookie on;
        testcookie_lifetime off;
    }
    location / {
        testcookie on;
    }
--- user_files
>>> old/index.html
It works!
--- request eval
["GET /old/", "GET /"]
--- more_headers
Cookie: BPC=87397509174b26fffd76bf2ab56b9b09
--- error_code eval
[200, 307]

=== TEST 12: a signed cookie passes until its own expiry, even past a lowered lifetime
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 10s;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers eval
"Cookie: BPC=" . main::signed(time() + 86400, $main::S1, '127.0.0.1')
--- error_code: 200

=== TEST 13: $testcookie_ok in "testcookie var" mode
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie var;
        return 200 "ok=$testcookie_ok";
    }
--- request eval
["GET /", "GET /"]
--- more_headers eval
["Cookie: BPC=" . main::signed(time() + 60, $main::S1, '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() - 60, $main::S1, '127.0.0.1')]
--- response_body eval
["ok=1", "ok=0"]

=== TEST 14: the lifetime needs a secret
--- http_config
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location / {
        testcookie on;
    }
--- must_die
--- error_log
"testcookie_lifetime" needs "testcookie_secret"

=== TEST 15: zero is not a lifetime
--- http_config
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_lifetime 0;
--- config
--- must_die
--- error_log
invalid value

=== TEST 16: a short previous secret
--- http_config
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_previous_secret short;
--- config
--- must_die
--- error_log
"testcookie_previous_secret" directive is too short

=== TEST 17: a random previous secret
--- http_config
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_previous_secret random;
--- config
--- must_die
--- error_log
"testcookie_previous_secret" directive cannot be "random"

=== TEST 18: secrets longer than the SHA-256 block and exactly one block long, set per location
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location /long/ {
        testcookie on;
        testcookie_secret 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789;
    }
    location /block/ {
        testcookie on;
        testcookie_secret 0123456789012345678901234567890123456789012345678901234567890123;
        testcookie_previous_secret 01234567890123456789012345678901234567890123456789012345678901234567890123456789;
    }
--- user_files
>>> long/index.html
It works!
>>> block/index.html
It works!
--- request eval
["GET /long/", "GET /block/", "GET /block/", "GET /long/"]
--- more_headers eval
["Cookie: BPC=" . main::signed(time() + 60, '0123456789' x 10, '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() + 60, '0123456789' x 6 . '0123', '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() + 60, '0123456789' x 8, '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() + 60, $main::S1, '127.0.0.1')]
--- error_code eval
[200, 200, 200, 307]
