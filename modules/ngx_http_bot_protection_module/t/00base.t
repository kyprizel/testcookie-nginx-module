#vi:filetype=perl


use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * 3 * blocks() - 7;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: Basic GET request, empty attempt counter
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
--- config
        testcookie on;
--- request
GET /?a=test HTTP/1.1
--- response_headers
Location: http://localhost:30001/?a=test&tstc=1
Set-Cookie: BPC=4cfb861a6a81106e7660f6eab1d10e0b; path=/
--- error_code: 307


=== TEST 2: Basic GET request, attempt counter 1
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
--- config
        testcookie on;
--- request
GET /?a=test&tstc=1 HTTP/1.1
--- response_headers
Location: http://localhost:30001/?a=test&tstc=2
Set-Cookie: BPC=4cfb861a6a81106e7660f6eab1d10e0b; path=/
--- error_code: 307


=== TEST 3: Basic GET request, attempt counter 3
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
--- config
        testcookie on;
--- request
GET /?a=test&tstc=3 HTTP/1.1
--- response_headers
Location: http://google.com/cookies.html?backurl=http://localhost/?a=test&tstc=3
--- error_code: 307

=== TEST 4: Basic GET request, session key user-agent
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
--- config
        testcookie on;
--- request
GET /?a=test HTTP/1.1
--- more_headers
User-Agent: Mozilla
--- response_headers
Location: http://localhost:30001/?a=test&tstc=1
Set-Cookie: BPC=30f59f604967b09bb8f1e21caf869cb3; path=/
--- error_code: 307

=== TEST 5: Basic GET request, META refresh
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
--- config
        testcookie on;
--- request
GET /?a=test
--- more_headers
User-Agent: Mozilla
--- response_headers
Set-Cookie: BPC=30f59f604967b09bb8f1e21caf869cb3; path=/
--- error_code: 200

=== TEST 6: Basic GET request, whitelist
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;

    testcookie_whitelist {
        8.8.8.8/32;
        127.0.0.1/32;
    }
--- config
        testcookie on;
--- request
GET /?a=test
--- error_code: 200
--- response_body_like eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== TEST 7: Basic GET request, no config arg name
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
--- config
        testcookie on;
--- request
GET /?a=test HTTP/1.1
--- more_headers
User-Agent: Mozilla
--- response_headers
Location: http://localhost:30001/?a=test
Set-Cookie: BPC=30f59f604967b09bb8f1e21caf869cb3; path=/
--- error_code: 307

=== TEST 8: Basic GET request, secret changed
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret anothersecret;
    testcookie_arg tstc;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
--- config
        testcookie on;
--- request
GET /?a=test HTTP/1.1
--- more_headers
User-Agent: Mozilla
Location: http://localhost:30001/?a=test&tstc=1
Set-Cookie: BPC=dfdba774f493bc0605000b22132f745a; path=/
--- error_code: 307

=== TEST 9: Basic GET request, custom refresh template
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template 'hello world!';
--- config
        testcookie on;
--- request
GET /?a=test
--- error_code: 200
--- response_body_like eval
"hello world!"

=== TEST 10: Basic GET request, whitelisting
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template 'hello world!';
    testcookie_whitelist {
        127.0.0.1/32;
    }
--- config
        testcookie on;
--- request
GET /?a=test
--- error_code: 200
--- response_body_like eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== TEST 11: Basic GET request, complex rewrite, test internal redirects
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_internal on;
--- config
        testcookie on;
        rewrite ^/(.*)$ /index.html?$1 last;
--- request
GET /test HTTP/1.1
--- response_headers
Location: http://localhost:30001/index.html?test&tstc=1
Set-Cookie: BPC=4cfb861a6a81106e7660f6eab1d10e0b; path=/
--- error_code: 307

=== TEST 12: Basic GET request, test user-agent if condition
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_internal on;
--- config
        location / {
            if ($http_user_agent = "test") {
                testcookie on;
            }
        }
--- request
GET /?xxx HTTP/1.1
--- more_headers
User-Agent: test
--- response_headers
Location: http://localhost:30001/?xxx&tstc=1
Set-Cookie: BPC=c6d90bd3e1bab267f80a4ef605cf61d0; path=/
--- error_code: 307

=== TEST 13: Basic GET request, empty attempt counter, HTTP version 1.0
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
--- config
        testcookie on;
--- request
GET /?a=test HTTP/1.0
--- response_headers
Location: http://localhost:30001/?a=test&tstc=1
Set-Cookie: BPC=4cfb861a6a81106e7660f6eab1d10e0b; path=/
--- error_code: 302
