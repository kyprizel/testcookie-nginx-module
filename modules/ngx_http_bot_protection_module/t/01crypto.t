#vi:filetype=perl


use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks() * 2;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: Basic GET request, custom refresh template, encrypted variables, static key
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key deadbeefdeadbeefdeadbeefdeadbeef;
    testcookie_refresh_encrypt_cookie_iv deadbeefdeadbeefdeadbeefdeadbeef;
--- config
        testcookie on;
--- request
GET /?a=test
--- error_code: 200
--- response_body_like eval
"cc54797809d466c4dc3a40a83c472ddd deadbeefdeadbeefdeadbeefdeadbeef deadbeefdeadbeefdeadbeefdeadbeef"

=== TEST 2: Basic GET request, custom refresh template, encrypted variables, random key
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key random;
    testcookie_refresh_encrypt_cookie_iv deadbeefdeadbeefdeadbeefdeadbeef;
--- config
        testcookie on;
--- request
GET /?a=test
--- error_code: 200
--- response_body_like eval
'^(\w){32} deadbeefdeadbeefdeadbeefdeadbeef (\w){32}$'

=== TEST 3: Basic GET request, custom refresh template, encrypted variables, random iv
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key deadbeefdeadbeefdeadbeefdeadbeef;
    testcookie_refresh_encrypt_cookie_iv random;
--- config
        testcookie on;
--- request
GET /?a=test
--- error_code: 200
--- response_body_like eval
'^(\w){32} (\w){32} deadbeefdeadbeefdeadbeefdeadbeef$'

=== TEST 4: Basic GET request, custom refresh template, encrypted variables, random key and iv
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key random;
    testcookie_refresh_encrypt_cookie_iv random;
--- config
        testcookie on;
--- request
GET /?a=test
--- error_code: 200
--- response_body_like eval
'^(\w){32} (\w){32} (\w){32}$'

=== TEST 5: Basic GET request, custom refresh template, encrypted variables, random key and iv, generated once, after server restart
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key random;
    testcookie_refresh_encrypt_cookie_iv random2;
--- config
        testcookie on;
--- request
GET /?a=test
--- error_code: 200
--- response_body_like eval
'^(\w){32} (\w){32} (\w){32}$'

=== TEST 6: HEAD request, custom refresh template, encrypted variables, random key and iv, generated once, after server restart
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg tstc;
    testcookie_max_attempts 3;
    testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template '$testcookie_enc_set $testcookie_enc_iv $testcookie_enc_key';

    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key random;
    testcookie_refresh_encrypt_cookie_iv random2;
--- config
        testcookie on;
--- request
GET /?a=test
--- response_headers
Content-Length: 98
--- error_code: 200
