#vi:filetype=perl

# The cookie a client sends back: where it is found, what passes, what is challenged again.
# Expected values are md5("127.0.0.1" . secret), computed outside the module:
#   printf '127.0.0.1flagmebla-flagmebla-flagmebla-flagmebla' | md5sum   -> 87397509174b26fffd76bf2ab56b9b09

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * 27;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: valid cookie passes
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers
Cookie: BPC=87397509174b26fffd76bf2ab56b9b09
--- error_code: 200
--- response_body_like: It works!


=== TEST 2: valid cookie after another cookie passes
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers
Cookie: _ga=GA1.1.123; wp-settings-1=x; BPC=87397509174b26fffd76bf2ab56b9b09
--- error_code: 200
--- response_body_like: It works!


=== TEST 3: valid cookie before another cookie passes
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers
Cookie: BPC=87397509174b26fffd76bf2ab56b9b09; foo=bar
--- error_code: 200
--- response_body_like: It works!


=== TEST 4: valid cookie in a second Cookie header passes
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers
Cookie: foo=bar
Cookie: BPC=87397509174b26fffd76bf2ab56b9b09
--- error_code: 200
--- response_body_like: It works!


=== TEST 5: wrong cookie value is challenged again with the right one
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers
Cookie: BPC=00000000000000000000000000000000
--- response_headers
Location: http://localhost/?tstc=1
Set-Cookie: BPC=87397509174b26fffd76bf2ab56b9b09; path=/; SameSite=None; Secure
--- error_code: 307


=== TEST 6: cookie of a wrong length is challenged
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers
Cookie: BPC=87397509174b26fffd76bf2ab56b9b0
--- error_code: 307


=== TEST 7: cookie with the right value under another name is challenged
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- more_headers
Cookie: XBPC=87397509174b26fffd76bf2ab56b9b09
--- error_code: 307


=== TEST 8: attempts used up, no fallback: 403
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
--- config
    location / {
        testcookie on;
    }
--- request
GET /?tstc=3
--- error_code: 403


=== TEST 9: POST is not challenged with get_only on (static module answers 405)
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_get_only on;
--- config
    location / {
        testcookie on;
    }
--- request
POST /
a=b
--- error_code: 405


=== TEST 10: POST is challenged with get_only off
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_get_only off;
--- config
    location / {
        testcookie on;
    }
--- request
POST /
a=b
--- response_headers
Set-Cookie: BPC=87397509174b26fffd76bf2ab56b9b09; path=/; SameSite=None; Secure
--- error_code: 307


=== TEST 11: var mode never challenges and fills the variables (no cookie)
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
--- config
    location / {
        testcookie var;
        add_header X-TC-OK $testcookie_ok;
        add_header X-TC-SET $testcookie_set;
    }
--- request
GET /
--- response_headers
X-TC-OK: 0
X-TC-SET: 87397509174b26fffd76bf2ab56b9b09
--- error_code: 200


=== TEST 12: var mode with the right cookie: ok 1, got = set
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
--- config
    location / {
        testcookie var;
        add_header X-TC-OK $testcookie_ok;
        add_header X-TC-GOT $testcookie_got;
    }
--- request
GET /
--- more_headers
Cookie: foo=bar; BPC=87397509174b26fffd76bf2ab56b9b09
--- response_headers
X-TC-OK: 1
X-TC-GOT: 87397509174b26fffd76bf2ab56b9b09
--- error_code: 200


=== TEST 13: port_in_redirect on keeps the port in Location
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg tstc;
    testcookie_port_in_redirect on;
--- config
    location / {
        testcookie on;
    }
--- request
GET /x?a=1
--- response_headers_like
Location: ^http://localhost:\d+/x\?a=1&tstc=1$
--- error_code: 307


=== TEST 14: a whitelisted address passes without a cookie
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_whitelist {
        127.0.0.0/8;
    }
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- error_code: 200
--- response_body_like: It works!
