#vi:filetype=perl

# The decoy: $testcookie_decoy / $testcookie_enc_decoy look like the cookie, $testcookie_trapped = 1 when a client
# sends the decoy back. Decoy key = SHA-256("testcookie decoy" . secret). Without testcookie_lifetime the decoy is
# HMAC-SHA256(decoy key, session) cut to 16 bytes; with it, expiry . HMAC-SHA256(decoy key, expiry . session) cut
# to 12, with the expiry of the real cookie. Expected values are computed here or with openssl, outside the module:
#   decoy for 127.0.0.1                         f1cc37eafe18d5e701b36edc8dadaa9a
#   AES-128-CBC of it, key = iv = deadbeef x 4  df703bf247bd5353c3b88bb7deef5417

use lib 'lib';
use Test::Nginx::Socket;
use Digest::SHA qw(sha256 hmac_sha256);

our $S1 = 'flagmebla-flagmebla-flagmebla-flagmebla';
our $DK = sha256('testcookie decoy' . $S1);

sub signed {
    my ($expiry, $key, $session) = @_;
    my $e = pack('N', $expiry);
    return unpack('H*', $e . substr(hmac_sha256($e . $session, $key), 0, 12));
}

sub decoy_legacy {
    return unpack('H*', substr(hmac_sha256($_[0], $DK), 0, 16));
}

# what the module may print for "set=<real> decoy=<decoy>" with a lifetime of 3600 s, from now on
sub signed_pair_re {
    my $now = time();
    my $alt = join '|', map {
        'set=' . signed($now + 3600 + $_, $S1, '127.0.0.1') . ' decoy=' . signed($now + 3600 + $_, $DK, '127.0.0.1')
    } (-2 .. 30);
    return qr/^(?:$alt)$/;
}

plan tests => repeat_each(1) * 37;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: the decoy differs from the cookie and is fixed for a session
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
--- config
    location = /t {
        testcookie var;
        return 200 "set=$testcookie_set decoy=$testcookie_decoy";
    }
--- request
GET /t
--- response_body eval
"set=87397509174b26fffd76bf2ab56b9b09 decoy=" . main::decoy_legacy('127.0.0.1')

=== TEST 2: sending the decoy back is trapped, nothing else is
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
--- config
    location = /t {
        testcookie var;
        return 200 "ok=$testcookie_ok trapped=$testcookie_trapped";
    }
--- request eval
["GET /t", "GET /t", "GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Cookie: BPC=" . main::decoy_legacy('127.0.0.1'),
 "Cookie: BPC=87397509174b26fffd76bf2ab56b9b09",
 "X-None: 1",
 "Cookie: BPC=00112233445566778899aabbccddeeff",
 "Cookie: BPC=" . main::decoy_legacy('10.0.0.1')]
--- response_body eval
["ok=0 trapped=1", "ok=1 trapped=0", "ok=0 trapped=0", "ok=0 trapped=0", "ok=0 trapped=0"]

=== TEST 3: the encrypted decoy uses the key and iv of the page
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template '$testcookie_enc_key $testcookie_enc_iv $testcookie_enc_set $testcookie_enc_decoy';
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key deadbeefdeadbeefdeadbeefdeadbeef;
    testcookie_refresh_encrypt_cookie_iv deadbeefdeadbeefdeadbeefdeadbeef;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- error_code: 200
--- response_body chomp
deadbeefdeadbeefdeadbeefdeadbeef deadbeefdeadbeefdeadbeefdeadbeef fe58413891e39e920fc73b22261b7606 df703bf247bd5353c3b88bb7deef5417

=== TEST 4: without encryption there is no encrypted decoy
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
--- config
    location = /t {
        testcookie var;
        return 200 "enc=$testcookie_enc_decoy";
    }
--- request
GET /t
--- response_body chomp
enc=

=== TEST 5: with a lifetime the decoy carries the expiry of the real cookie
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location = /t {
        testcookie var;
        return 200 "set=$testcookie_set decoy=$testcookie_decoy";
    }
--- request
GET /t
--- response_body_like eval
main::signed_pair_re()

=== TEST 6: with a lifetime a decoy is trapped even after its expiry, the real cookie never is
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location = /t {
        testcookie var;
        return 200 "ok=$testcookie_ok trapped=$testcookie_trapped";
    }
--- request eval
["GET /t", "GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Cookie: BPC=" . main::signed(time() + 60, $main::DK, '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() - 60, $main::DK, '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() + 60, $main::S1, '127.0.0.1'),
 "Cookie: BPC=" . main::signed(time() - 60, $main::S1, '127.0.0.1')]
--- response_body eval
["ok=0 trapped=1", "ok=0 trapped=1", "ok=1 trapped=0", "ok=0 trapped=0"]

=== TEST 7: a trapped client is challenged again, and the variable works before the access phase
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
--- config
    location / {
        testcookie on;
    }
    location /guarded/ {
        testcookie on;
        if ($testcookie_trapped = 1) {
            return 403;
        }
    }
--- user_files
>>> guarded/index.html
It works!
--- request eval
["GET /", "GET /guarded/", "GET /guarded/"]
--- more_headers eval
["Cookie: BPC=" . main::decoy_legacy('127.0.0.1'),
 "Cookie: BPC=" . main::decoy_legacy('127.0.0.1'),
 "Cookie: BPC=87397509174b26fffd76bf2ab56b9b09"]
--- error_code eval
[307, 403, 200]

=== TEST 8: a whitelisted client has no decoy and is never trapped
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_whitelist {
        127.0.0.1/32;
    }
--- config
    location = /t {
        testcookie var;
        return 200 "decoy=$testcookie_decoy trapped=$testcookie_trapped";
    }
--- request
GET /t
--- more_headers eval
"Cookie: BPC=" . main::decoy_legacy('127.0.0.1')
--- response_body chomp
decoy= trapped=0

=== TEST 9: no secret, no decoy
--- http_config
    testcookie_name BPC;
    testcookie_session $remote_addr;
--- config
    location = /t {
        testcookie var;
        return 200 "decoy=$testcookie_decoy trapped=$testcookie_trapped";
    }
--- request
GET /t
--- response_body chomp
decoy= trapped=0

=== TEST 10: with the module off the variables are empty
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
--- config
    location = /t {
        testcookie off;
        return 200 "decoy=$testcookie_decoy trapped=$testcookie_trapped";
    }
--- request
GET /t
--- more_headers eval
"Cookie: BPC=" . main::decoy_legacy('127.0.0.1')
--- response_body chomp
decoy= trapped=

=== TEST 11: a location with its own secret has its own decoy
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
--- config
    location = /t {
        testcookie var;
        testcookie_secret anothersecret-anothersecret-anothersecret;
        return 200 "decoy=$testcookie_decoy";
    }
--- request
GET /t
--- response_body eval
"decoy=" . unpack('H*', substr(Digest::SHA::hmac_sha256('127.0.0.1',
    Digest::SHA::sha256('testcookie decoy' . 'anothersecret-anothersecret-anothersecret')), 0, 16))
