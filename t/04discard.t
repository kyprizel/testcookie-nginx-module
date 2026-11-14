#vi:filetype=perl

# A POST answered with the refresh page must have its body discarded. Otherwise, on a keep-alive HTTP/1.1
# connection, nginx reads the unread body as the start of the next request: the next request breaks (400)
# and the body - a login form with its password, say - is written to the logs as a request line.
# Each test sends two requests on one connection: a challenged POST, then a request to a location without
# the challenge.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * 18;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: custom refresh template: the POST body does not become the next request
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_get_only off;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template 'challenge';
--- config
    location / {
        testcookie on;
    }
    location = /free {
        return 200 "free";
    }
--- pipelined_requests eval
["POST /login\nlog=admin&pwd=secret-password", "GET /free"]
--- error_code eval
[200, 200]
--- response_body eval
["challenge", "free"]
--- no_error_log
secret-password
--- log_level: info


=== TEST 2: built-in refresh page: the POST body does not become the next request
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_get_only off;
    testcookie_redirect_via_refresh on;
--- config
    location / {
        testcookie on;
    }
    location = /free {
        return 200 "free";
    }
--- pipelined_requests eval
["POST /login\nlog=admin&pwd=secret-password", "GET /free"]
--- error_code eval
[200, 200]
--- response_body_like eval
["Refresh", "^free\$"]
--- no_error_log
secret-password
--- log_level: info


=== TEST 3: plain 307 redirect (nginx discards the body itself): the next request is intact too
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
    location = /free {
        return 200 "free";
    }
--- pipelined_requests eval
["POST /login\nlog=admin&pwd=secret-password", "GET /free"]
--- error_code eval
[307, 200]
--- response_body_like eval
["", "^free\$"]
--- no_error_log
secret-password
--- log_level: info
