# vim:set ft= ts=4 sw=4 et fdm=marker:

use lib 'lib';
use Test::Nginx::Socket;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

#no_shuffle();

plan tests => repeat_each() * (blocks() * 5);

run_tests();

__DATA__

=== TEST 1: replace_filter_last_modified clear
--- config
    default_type text/html;
    replace_filter_last_modified clear;
    location /t {
        content_by_lua '
            ngx.header["Last-Modified"] = "Wed, 20 Nov 2013 05:30:35 GMT"
            ngx.say("ok")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
ok
--- response_headers
!Last-Modified
--- no_error_log
[alert]
[error]



=== TEST 2: replace_filter_last_modified keep
--- config
    default_type text/html;
    replace_filter_last_modified keep;
    location /t {
        content_by_lua '
            ngx.header["Last-Modified"] = "Wed, 20 Nov 2013 05:30:35 GMT"
            ngx.say("ok")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
ok
--- response_headers
Last-Modified: Wed, 20 Nov 2013 05:30:35 GMT
--- no_error_log
[alert]
[error]



=== TEST 3: replace_filter_last_modified default to clear
--- config
    default_type text/html;
    #replace_filter_last_modified clear;
    location /t {
        content_by_lua '
            ngx.header["Last-Modified"] = "Wed, 20 Nov 2013 05:30:35 GMT"
            ngx.say("ok")
        ';
        replace_filter abcabd X;
    }
--- request
GET /t

--- response_body
ok
--- response_headers
!Last-Modified
--- no_error_log
[alert]
[error]

