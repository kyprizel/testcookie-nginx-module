# vim:set ft= ts=4 sw=4 et fdm=marker:

use lib 'lib';
use Test::Nginx::Socket;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

#no_shuffle();

plan tests => repeat_each() * (blocks() * 4 + 3);

our $StapOutputChains = <<'_EOC_';
global active

F(ngx_http_handler) {
    active = 1
}

/*
F(ngx_http_write_filter) {
    if (active && pid() == target()) {
        printf("http writer filter: %s\n", ngx_chain_dump($in))
    }
}
*/

F(ngx_http_chunked_body_filter) {
    if (active && pid() == target()) {
        printf("http chunked filter: %s\n", ngx_chain_dump($in))
    }
}

F(ngx_http_replace_output) {
    if (active && pid() == target()) {
        printf("http replace output: %s\n", ngx_chain_dump($ctx->out))
    }
}

probe syscall.writev {
    if (active && pid() == target()) {
        printf("writev(%s)", ngx_iovec_dump($vec, $vlen))
        /*
        for (i = 0; i < $vlen; i++) {
            printf(" %p [%s]", $vec[i]->iov_base, text_str(user_string_n($vec[i]->iov_base, $vec[i]->iov_len)))
        }
        */
    }
}

probe syscall.writev.return {
    if (active && pid() == target()) {
        printf(" = %s\n", retstr)
    }
}

_EOC_

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: nginx vars (global)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        set $foo X;
        echo abc;
        replace_filter . $foo g;
    }
--- request
GET /t

--- stap
F(ngx_http_replace_non_capturing_parse) {
    println("non capturing parse")
}

F(ngx_http_replace_capturing_parse) {
    println("capturing parse")
}

--- stap_out_like chop
^(non capturing parse\n)+$

--- response_body chop
XXXX
--- no_error_log
[alert]
[error]



=== TEST 2: nginx vars (non-global)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        set $foo X;
        echo abc;
        replace_filter . $foo;
    }
--- request
GET /t

--- stap
F(ngx_http_replace_non_capturing_parse) {
    println("non capturing parse")
}

F(ngx_http_replace_capturing_parse) {
    println("capturing parse")
}

--- stap_out_like chop
^(non capturing parse\n)+$

--- response_body
Xbc
--- no_error_log
[alert]
[error]



=== TEST 3: undefined nginx vars
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo abc;
        replace_filter . $foo;
    }
--- request
GET /t
--- response_body
Xbc
--- no_error_log
[alert]
[error]
--- SKIP



=== TEST 4: use of capturing variables
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo abc;
        replace_filter . $1;
    }
--- request
GET /t
--- response_body
Xbc
--- no_error_log
[alert]
[error]
--- SKIP



=== TEST 5: more contexts
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        set $foo X;
        echo abc;
        replace_filter . "[$foo]";
    }
--- request
GET /t
--- response_body
[X]bc
--- no_error_log
[alert]
[error]



=== TEST 6: more nginx vars
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        set $foo X;
        set $bar Y;
        echo abc;
        replace_filter . "[$foo,$bar]";
    }
--- request
GET /t
--- response_body
[X,Y]bc
--- no_error_log
[alert]
[error]



=== TEST 7: various lengths of nginx var values
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        set $foo XYZ;
        set $bar "";
        echo abc;
        replace_filter . "[$foo,$bar]";
    }
--- request
GET /t
--- response_body
[XYZ,]bc
--- no_error_log
[alert]
[error]



=== TEST 8: escaping the dollar sign
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        set $foo X;
        set $bar Y;
        echo abc;
        replace_filter . "[$foo,$$bar]";
    }
--- request
GET /t
--- response_body
[X,$bar]bc
--- no_error_log
[alert]
[error]



=== TEST 9: \ is not an escaping sequence
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        set $foo X;
        set $bar Y;
        echo abc;
        replace_filter . "[\$foo,\$bar]";
    }
--- request
GET /t
--- response_body
[\X,\Y]bc
--- no_error_log
[alert]
[error]



=== TEST 10: cached subs values
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        set $foo X;
        echo abc;
        replace_filter . "$foo" g;
    }
--- request
GET /t
--- response_body chop
XXXX

--- stap
F(ngx_http_replace_complex_value) {
    println("complex value")
}

--- stap_out
complex value

--- no_error_log
[alert]
[error]

