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
no_long_string();
run_tests();

__DATA__

=== TEST 1: 1-byte chain bufs (0)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;

    location = /t {
        echo -n a;
        echo -n b;
        echo -n a;
        echo -n b;
        echo -n a;
        echo -n c;
        echo d;
        replace_filter abac [$&];
    }
--- request
GET /t
--- stap2 eval: $::StapOutputChains
--- stap3
probe process("nginx").statement("*@ngx_http_replace_filter_module.c:1413") {
    //printf("chain: %s", ngx_chain_dump($ctx->busy))
    print_ubacktrace()
}

--- response_body
ababacd
--- error_log
replace filter: exceeding replace_filter_max_buffered_size (0): 1
--- no_error_log
[error]



=== TEST 2: 1-byte chain bufs (1)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 1;

    location = /t {
        echo -n a;
        echo -n b;
        echo -n a;
        echo -n b;
        echo -n a;
        echo -n c;
        echo d;
        replace_filter abac [$&];
    }
--- request
GET /t
--- stap2 eval: $::StapOutputChains
--- stap3
probe process("nginx").statement("*@ngx_http_replace_filter_module.c:1439") {
    //printf("chain: %s", ngx_chain_dump($ctx->busy))
    print_ubacktrace()
    exit()
}

--- response_body
ababacd
--- error_log
replace filter: exceeding replace_filter_max_buffered_size (1): 2
--- no_error_log
[error]



=== TEST 3: 1-byte chain bufs (2)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 2;

    location = /t {
        echo -n a;
        echo -n b;
        echo -n a;
        echo -n b;
        echo -n a;
        echo -n c;
        echo d;
        replace_filter abac [$&];
    }
--- request
GET /t
--- stap2 eval: $::StapOutputChains
--- stap3
probe process("nginx").statement("*@ngx_http_replace_filter_module.c:1439") {
    //printf("chain: %s", ngx_chain_dump($ctx->busy))
    print_ubacktrace()
    exit()
}

--- response_body
ababacd
--- error_log
replace filter: exceeding replace_filter_max_buffered_size (2): 3
--- no_error_log
[error]



=== TEST 4: trim both leading and trailing spaces (1 byte at a time) (6)
--- config
    replace_filter_max_buffered_size 6;
    default_type text/html;
    location /a.html {
        internal;
    }

    location = /t {
        content_by_lua '
            local res = ngx.location.capture("/a.html")
            local txt = res.body
            for i = 1, string.len(txt) do
                ngx.print(string.sub(txt, i, i))
                ngx.flush(true)
            end
        ';
        replace_filter '^\s+|\s+$' '[$&]' g;
    }
--- user_files
>>> a.html
  hello, world  
blah yeah
hello  
   baby!
     
abc

--- stap2
F(ngx_palloc) {
    if ($size < 0) {
        print_ubacktrace()
        exit()
    }
}
--- stap3
probe process("nginx").statement("*@ngx_http_replace_filter_module.c:1438") {
    //printf("chain: %s", ngx_chain_dump($ctx->busy))
    print_ubacktrace()
    exit()
}

--- request
GET /t
--- response_body
[  ]hello, world[  ]
blah yeah
hello[  ]
[   ]baby!
     
abc

--- error_log
replace filter: exceeding replace_filter_max_buffered_size (6): 7
--- no_error_log
[error]



=== TEST 5: github issue #2: error "general look-ahead not supported"
--- config
    replace_filter_max_buffered_size 0;
    location /t {
         charset utf-8;
         default_type text/html;
         echo "ABCabcABCabc";
         #replace_filter_types text/plain;
         replace_filter "a.+a" "[$&]" "ig";
     }
--- request
GET /t

--- stap3
probe process("nginx").statement("*@ngx_http_replace_filter_module.c:1481") {
    print_ubacktrace()
}

--- response_body
ABCabcABCabc
--- error_log
replace filter: exceeding replace_filter_max_buffered_size (0): 12
--- no_error_log
[error]



=== TEST 6: backtrack to the middle of a pending capture (pending: output|capture + rematch) (0)
--- config
    replace_filter_max_buffered_size 0;
    default_type text/html;
    location = /t {
        echo -n ab;
        echo -n c;
        echo d;
        replace_filter 'abce|b' '[$&]' g;
    }

--- stap2
probe process("nginx").statement("*@ngx_http_replace_filter_module.c:1492") {
    print_ubacktrace()
}

--- stap3 eval: $::StapOutputChains
--- request
GET /t
--- response_body
abcd

--- error_log
replace filter: exceeding replace_filter_max_buffered_size (0): 2
--- no_error_log
[error]



=== TEST 7: backtrack to the middle of a pending capture (pending: output|capture + rematch) (1)
--- config
    replace_filter_max_buffered_size 1;
    default_type text/html;
    location = /t {
        echo -n ab;
        echo -n c;
        echo d;
        replace_filter 'abce|b' '[$&]' g;
    }

--- stap2
probe process("nginx").statement("*@ngx_http_replace_filter_module.c:1501") {
    print_ubacktrace()
}

--- stap3 eval: $::StapOutputChains
--- request
GET /t
--- response_body
abcd

--- error_log
replace filter: exceeding replace_filter_max_buffered_size (1): 2
--- no_error_log
[error]

