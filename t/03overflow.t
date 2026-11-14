#vi:filetype=perl

# Two heap buffer overflows (fixed): "testcookie_secret random" wrote 16 bytes into the 7-byte "random" token
# at config load; "testcookie_expires" past 2037 overran the Set-Cookie buffer on every challenge (4-digit year).
# Without AddressSanitizer they pass silently: run them under an ASAN build (with -DNGX_DEBUG_PALLOC=1, or the pool
# allocator hides the overrun) and treat any ASAN report as a failure.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * 6;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: testcookie_secret random starts and challenges with a 32-hex cookie
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret random;
    testcookie_session $remote_addr;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- response_headers_like
Set-Cookie: ^BPC=[0-9a-f]{32}; path=/; SameSite=None; Secure$
--- error_code: 307


=== TEST 2: testcookie_expires 20y gives a 4-digit year past 2037
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_expires 20y;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- response_headers_like
Set-Cookie: ^BPC=87397509174b26fffd76bf2ab56b9b09; expires=\w{3}, \d\d-\w{3}-20[4-9]\d \d\d:\d\d:\d\d GMT; path=/; SameSite=None; Secure$
--- error_code: 307


=== TEST 3: testcookie_expires max keeps its fixed date
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_expires max;
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- response_headers_like
Set-Cookie: ^BPC=87397509174b26fffd76bf2ab56b9b09; expires=Thu, 31-Dec-37 23:55:55 GMT; path=/; SameSite=None; Secure$
--- error_code: 307
