#vi:filetype=perl

# testcookie_refresh_template_file: the refresh page read from a file when nginx reads its configuration.
# It works like the string of testcookie_refresh_template: the same variables, the same inheritance,
# and "testcookie_refresh_template none" switches off an inherited file.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * 33;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: page from a file, absolute path, variables filled in
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/refresh.html;
--- config
    location /t {
        testcookie on;
    }
--- user_files eval
[["refresh.html", "<p>set=\$testcookie_set next=\$testcookie_nexturl ok=\$testcookie_ok</p>\n"]]
--- request
GET /t
--- error_code: 200
--- response_headers
Content-Type: text/html
Content-Length: 73
--- response_body
<p>set=87397509174b26fffd76bf2ab56b9b09 next=http://localhost/t ok=0</p>

=== TEST 2: relative path is taken from the configuration directory, like include
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template_file ../html/refresh.html;
--- config
    location /t {
        testcookie on;
    }
--- user_files eval
[["refresh.html", "relative \$testcookie_set"]]
--- request
GET /t
--- error_code: 200
--- response_body chomp
relative 87397509174b26fffd76bf2ab56b9b09

=== TEST 3: a page without variables is sent byte for byte
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/static.html;
--- config
    location /t {
        testcookie on;
    }
--- user_files eval
[["static.html", "<html>\r\n\t<body>\x{00}\x{ff}'\"\\</body>\r\n</html>"]]
--- request
GET /t
--- error_code: 200
--- response_headers
Content-Length: 36
--- response_body eval
"<html>\r\n\t<body>\x{00}\x{ff}'\"\\</body>\r\n</html>"

=== TEST 4: HEAD gets the headers of the page and no body
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/refresh.html;
--- config
    location /t {
        testcookie on;
    }
--- user_files eval
[["refresh.html", "set=\$testcookie_set"]]
--- request
HEAD /t
--- error_code: 200
--- response_headers
Content-Length: 36
--- response_body

=== TEST 5: inherited by a location, switched off with testcookie_refresh_template none
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/refresh.html;
--- config
    location /file {
        testcookie on;
    }
    location /meta {
        testcookie on;
        testcookie_refresh_template none;
    }
--- user_files eval
[["refresh.html", "from the file"]]
--- request eval
["GET /file", "GET /meta"]
--- error_code eval
[200, 200]
--- response_body_like eval
["^from the file\$", "<meta http-equiv=\"Refresh\" content=\"0; URL=http://localhost/meta\">"]

=== TEST 6: a location may set its own string or its own file over an inherited file
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/refresh.html;
--- config
    location /string {
        testcookie on;
        testcookie_refresh_template 'string $testcookie_set';
    }
    location /other {
        testcookie on;
        testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/other.html;
    }
--- user_files eval
[["refresh.html", "from the file"], ["other.html", "other \$testcookie_set"]]
--- request eval
["GET /string", "GET /other"]
--- error_code eval
[200, 200]
--- response_body eval
["string 87397509174b26fffd76bf2ab56b9b09", "other 87397509174b26fffd76bf2ab56b9b09"]

=== TEST 7: encrypted variables in a file
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/refresh.html;
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key deadbeefdeadbeefdeadbeefdeadbeef;
    testcookie_refresh_encrypt_cookie_iv deadbeefdeadbeefdeadbeefdeadbeef;
--- config
    location /t {
        testcookie on;
    }
--- user_files eval
[["refresh.html", "\$testcookie_enc_set \$testcookie_enc_iv \$testcookie_enc_key"]]
--- request
GET /t
--- error_code: 200
--- response_body chomp
fe58413891e39e920fc73b22261b7606 deadbeefdeadbeefdeadbeefdeadbeef deadbeefdeadbeefdeadbeefdeadbeef

=== TEST 8: a literal dollar sign through a variable, nginx has no escape for it
--- http_config
    testcookie off;
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/refresh.html;
    geo $dollar {
        default "$";
    }
--- config
    location /t {
        testcookie on;
    }
--- user_files eval
[["refresh.html", "var \${dollar}x = '\$testcookie_set';"]]
--- request
GET /t
--- error_code: 200
--- response_body chomp
var $x = '87397509174b26fffd76bf2ab56b9b09';

=== TEST 9: the string and the file on one level
--- http_config
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_refresh_template 'string';
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/refresh.html;
--- config
--- user_files eval
[["refresh.html", "from the file"]]
--- must_die
--- error_log
"testcookie_refresh_template_file" directive is duplicate

=== TEST 10: missing file
--- http_config
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/nope.html;
--- config
--- must_die
--- error_log eval
qr{open\(\) ".*/html/nope\.html" failed}

=== TEST 11: empty file
--- http_config
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/empty.html;
--- config
--- user_files eval
[["empty.html", ""]]
--- must_die
--- error_log eval
qr{refresh template file ".*/html/empty\.html" is empty}

=== TEST 12: a bare dollar sign in the file names the file in the error
--- http_config
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_refresh_template_file $TEST_NGINX_SERVROOT/html/jquery.html;
--- config
--- user_files eval
[["jquery.html", "<script>\$(function () {});</script>"]]
--- must_die
--- error_log eval
[qr{invalid variable name}, qr{in refresh template file ".*/html/jquery\.html"}]
