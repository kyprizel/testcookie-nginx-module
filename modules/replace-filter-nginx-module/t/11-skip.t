# vim:set ft= ts=4 sw=4 et fdm=marker:

use lib 'lib';
use Test::Nginx::Socket;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

#no_shuffle();

plan tests => repeat_each() * (blocks() * 4);

run_tests();

__DATA__

=== TEST 1: skip true (constant)
--- config
    default_type text/html;
    replace_filter_skip 1;
    location /t {
        content_by_lua '
            ngx.say("abcabd")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
abcabd
--- no_error_log
[alert]
[error]



=== TEST 2: skip false (constant 0)
--- config
    default_type text/html;
    replace_filter_skip 0;
    location /t {
        content_by_lua '
            ngx.say("abcabd")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
X
--- no_error_log
[alert]
[error]



=== TEST 3: skip false (constant "")
--- config
    default_type text/html;
    replace_filter_skip "";
    location /t {
        content_by_lua '
            ngx.say("abcabd")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
X
--- no_error_log
[alert]
[error]



=== TEST 4: skip true (constant, random strings)
--- config
    default_type text/html;
    replace_filter_skip ab;
    location /t {
        content_by_lua '
            ngx.say("abcabd")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
abcabd
--- no_error_log
[alert]
[error]



=== TEST 5: skip variable (1)
--- config
    default_type text/html;
    set $skip '';
    replace_filter_skip $skip;
    location /t {
        content_by_lua '
            ngx.var.skip = 1
            ngx.say("abcabd")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
abcabd
--- no_error_log
[alert]
[error]



=== TEST 6: skip variable (0)
--- config
    default_type text/html;
    set $skip '';
    replace_filter_skip $skip;
    location /t {
        content_by_lua '
            ngx.var.skip = 0
            ngx.say("abcabd")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
X
--- no_error_log
[alert]
[error]



=== TEST 7: skip variable ("")
--- config
    default_type text/html;
    set $skip '';
    replace_filter_skip $skip;
    location /t {
        content_by_lua '
            ngx.var.skip = ""
            ngx.say("abcabd")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
X
--- no_error_log
[alert]
[error]



=== TEST 8: skip variable (nil)
--- config
    default_type text/html;
    set $skip '';
    replace_filter_skip $skip;
    location /t {
        content_by_lua '
            ngx.var.skip = nil
            ngx.say("abcabd")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
X
--- no_error_log
[alert]
[error]

