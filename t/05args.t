#vi:filetype=perl

# Looking for the attempt counter (testcookie_arg) in the query string must not read past its end.
# "i < args->len - look->len" on size_t wrapped around when the query was shorter than the argument name,
# and ngx_strncmp() then read past the query. On a request line that stays inside the header buffer and goes
# unnoticed; after an internal redirect (testcookie_internal on) the query is its own pool allocation and
# AddressSanitizer (with -DNGX_DEBUG_PALLOC=1) reports a heap-buffer-overflow READ in strncmp.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * 2 * blocks();
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: internal redirect to a query shorter than the argument name
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg attempt;
    testcookie_internal on;
--- config
    location = /go {
        rewrite ^ /t/?a last;
    }
    location /t/ {
        testcookie on;
    }
--- request
GET /go
--- response_headers_like
Location: ^http://localhost/go\?(a&)?attempt=1$
--- error_code: 307


=== TEST 2: query shorter than the argument name
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg attempt;
--- config
    location / {
        testcookie on;
    }
--- request
GET /?a
--- response_headers_like
Location: ^http://localhost/\?a&attempt=1$
--- error_code: 307


=== TEST 3: query exactly the argument name, no value
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg attempt;
--- config
    location / {
        testcookie on;
    }
--- request
GET /?attempt
--- response_headers_like
Location: ^http://localhost/\?attempt&attempt=1$
--- error_code: 307


=== TEST 4: the counter right at the end of the query is still found
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg attempt;
--- config
    location / {
        testcookie on;
    }
--- request
GET /?x=1&attempt=2
--- response_headers_like
Location: ^http://localhost/\?x=1&attempt=3$
--- error_code: 307


=== TEST 5: the shortest counter, the whole query
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_arg attempt;
--- config
    location / {
        testcookie on;
    }
--- request
GET /?attempt=1
--- response_headers_like
Location: ^http://localhost/\?attempt=2$
--- error_code: 307
