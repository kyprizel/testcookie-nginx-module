#vi:filetype=perl

# A whitelisted client passes before any cookie is computed. $testcookie_set used to dereference the missing
# value then, and the worker died with SIGSEGV (in ngx_hex_dump) on every whitelisted request, for example
# when $testcookie_set was in a log_format.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * 15;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: $testcookie_set for a whitelisted client is empty
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_whitelist {
        127.0.0.1/32;
    }
--- config
    location = /t {
        testcookie on;
        return 200 "set=$testcookie_set";
    }
--- request
GET /t
--- error_code: 200
--- response_body chomp
set=
--- no_error_log eval
qr/exited on signal|exited with code [1-9]/

=== TEST 2: $testcookie_set in a log_format, whitelisted client
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_whitelist {
        127.0.0.1/32;
    }
    log_format tc 'ok=$testcookie_ok set=$testcookie_set';
--- config
    access_log logs/tc.log tc;
    location / {
        testcookie on;
    }
--- request eval
# the log phase runs after the response is sent: nginx runs without a master process in the tests,
# so a crash there shows only as no answer to the next request
["GET /", "GET /"]
--- error_code eval
[200, 200]
--- response_body_like eval
["It works!", "It works!"]
--- no_error_log eval
qr/exited on signal|exited with code [1-9]/

=== TEST 3: every variable for a whitelisted client
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key random;
    testcookie_whitelist {
        127.0.0.1/32;
    }
--- config
    location = /t {
        testcookie on;
        return 200 "ok=$testcookie_ok set=$testcookie_set got=$testcookie_got enc=$testcookie_enc_set";
    }
--- request
GET /t
--- more_headers
Cookie: BPC=87397509174b26fffd76bf2ab56b9b09
--- error_code: 200
--- response_body chomp
ok=1 set= got= enc=
--- no_error_log eval
qr/exited on signal|exited with code [1-9]/

=== TEST 4: a client outside the whitelist still gets its value
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_whitelist {
        10.0.0.0/8;
    }
--- config
    location = /t {
        testcookie on;
        return 200 "set=$testcookie_set";
    }
--- request
GET /t
--- error_code: 200
--- response_body chomp
set=87397509174b26fffd76bf2ab56b9b09
--- no_error_log eval
qr/exited on signal|exited with code [1-9]/
