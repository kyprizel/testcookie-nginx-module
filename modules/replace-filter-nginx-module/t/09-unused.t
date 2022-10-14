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

=== TEST 1: used
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo abcabcabde;
        replace_filter abcabd X;
    }
--- request
GET /t

--- stap
F(ngx_http_replace_header_filter) {
    println("replace header filter")
}

F(ngx_http_replace_body_filter) {
    println("replace body filter")
}

--- stap_out
replace header filter
replace body filter
replace body filter

--- response_body
abcXe
--- no_error_log
[alert]
[error]



=== TEST 2: unused
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo abcabcabde;
        #replace_filter abcabd X;
    }
--- request
GET /t

--- stap
F(ngx_http_replace_header_filter) {
    println("replace header filter")
}

F(ngx_http_replace_body_filter) {
    println("replace body filter")
}

--- stap_out

--- response_body
abcabcabde
--- no_error_log
[alert]
[error]



=== TEST 3: used (multi http {} blocks)
This test case won't run with nginx 1.9.3+ since duplicate http {} blocks
have been prohibited since then.
--- SKIP
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo abcabcabde;
        replace_filter abcabd X;
    }
--- post_main_config
    http {
    }

--- request
GET /t

--- stap
F(ngx_http_replace_header_filter) {
    println("replace header filter")
}

F(ngx_http_replace_body_filter) {
    println("replace body filter")
}

--- stap_out
replace header filter
replace body filter
replace body filter

--- response_body
abcXe
--- no_error_log
[alert]
[error]

