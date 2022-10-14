# vim:set ft= ts=4 sw=4 et fdm=marker:

use lib 'lib';
use Test::Nginx::Socket;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

no_shuffle();

plan tests => repeat_each() * (blocks() * 4 + 5);

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

=== TEST 1: once patterns
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'hello world world hello';
        replace_filter world "<$&>";
        replace_filter hello "[$&]";
    }
--- request
GET /t
--- response_body
[hello] <world> world hello

--- stap
F(ngx_http_replace_non_capturing_parse) {
    println("non capturing parse")
}

F(ngx_http_replace_capturing_parse) {
    println("capturing parse")
}

--- stap_out_like chop
^(capturing parse\n)+$

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 2: once patterns
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'Hello world Hello world';
        replace_filter world "<$&>";
        replace_filter hello "[$&]";
    }
--- request
GET /t
--- response_body
Hello <world> Hello world

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 3: case-insensitive patterns
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'Hello world WORLD HELLO';
        replace_filter world "<$&>";
        replace_filter hello "[$&]" i;
    }
--- request
GET /t
--- response_body
[Hello] <world> WORLD HELLO

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 4: global subs
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'hello world world hello';
        replace_filter world "<$&>" g;
        replace_filter hello "[$&]" g;
    }
--- request
GET /t
--- response_body
[hello] <world> <world> [hello]

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 5: global subs (case sensitive)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'Hello World worlD hellO';
        replace_filter world "<$&>" g;
        replace_filter hello "[$&]" g;
    }
--- request
GET /t
--- response_body
Hello World worlD hellO

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 6: global subs (case insensitive)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'Hello World worlD hellO';
        replace_filter world "<$&>" ig;
        replace_filter hello "[$&]" g;
    }
--- request
GET /t
--- response_body
Hello <World> <worlD> hellO

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 7: global subs (case insensitive) (2)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'Hello World worlD hellO';
        replace_filter world "<$&>" g;
        replace_filter hello "[$&]" ig;
    }
--- request
GET /t
--- response_body
[Hello] World worlD [hellO]

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 8: global subs (case insensitive) (3)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'Hello World worlD hellO';
        replace_filter world "<$&>" gi;
        replace_filter hello "[$&]" ig;
    }
--- request
GET /t
--- response_body
[Hello] <World> <worlD> [hellO]

--- stap
F(ngx_http_replace_non_capturing_parse) {
    println("non capturing parse")
}

F(ngx_http_replace_capturing_parse) {
    println("capturing parse")
}

--- stap_out_like chop
^(capturing parse\n)+$

--- no_error_log
[alert]
[error]



=== TEST 9: global subs (case insensitive) - non-capturing
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo 'Hello World';
        replace_filter world "<>" gi;
        replace_filter hello "[]" ig;
    }
--- request
GET /t
--- response_body
[] <>

--- stap
F(ngx_http_replace_non_capturing_parse) {
    println("non capturing parse")
}

F(ngx_http_replace_capturing_parse) {
    println("capturing parse")
}

--- stap_out_like chop
^(non capturing parse\n)+$

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 10: working as a tokenizer
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        echo -n a;
        echo b;
        replace_filter a "[$&]" g;
        replace_filter ab "<$&>" g;
    }
--- request
GET /t
--- response_body
[a]b

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 11: working as a tokenizer (2)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 1;
    location /t {
        echo -n a;
        echo b;
        replace_filter ab "<$&>" g;
        replace_filter a "[$&]" g;
    }
--- request
GET /t
--- response_body
<ab>

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 12: on server level
--- config
    default_type text/html;
    replace_filter_max_buffered_size 1;
    replace_filter ab "<$&>" g;
    replace_filter a "[$&]" g;

    location /t {
        echo -n a;
        echo b;
    }
--- request
GET /t
--- response_body
<ab>

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 13: mixing once and global patterns
--- config
    default_type text/html;
    replace_filter_max_buffered_size 1;
    location /t {
        echo hello world hiya hiya world hello;
        replace_filter hello "<$&>";
        replace_filter hiya "{$&}";
        replace_filter world "[$&]" g;
    }
--- request
GET /t
--- response_body
<hello> [world] {hiya} hiya [world] hello

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 14: all once
--- config
    default_type text/html;
    replace_filter_max_buffered_size 1;
    location /t {
        echo hello world hiya hiya world hello;
        replace_filter hello "<$&>";
        replace_filter hiya "{$&}";
        replace_filter world "[$&]";
    }
--- request
GET /t
--- response_body
<hello> [world] {hiya} hiya world hello

--- stap
F(ngx_http_replace_complex_value) {
    println("complex value")
}

--- stap_out
complex value
complex value
complex value

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 15: all once (server level)
--- config
    default_type text/html;
    replace_filter_max_buffered_size 1;
    replace_filter hello "<$&>";
    replace_filter hiya "{$&}";
    replace_filter world "[$&]";

    location /t {
        echo hello world hiya hiya world hello;
    }
--- request
GET /t
--- response_body
<hello> [world] {hiya} hiya world hello

--- stap
F(ngx_http_replace_complex_value) {
    println("complex value")
}

--- stap_out
complex value
complex value
complex value

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]



=== TEST 16: remove C/C++ comments (1 byte at a time)
--- config
    replace_filter_max_buffered_size 50;
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
        replace_filter "'(?:\\\\[^\n]|[^'\n])*'" $& g;
        replace_filter '"(?:\\\\[^\n]|[^"\n])*"' $& g;
        replace_filter '/\*.*?\*/|//[^\n]*' '' g;
    }
--- user_files
>>> a.html
b = '"'; /* blah */ c = '"'
a = "h\"/* */";
 i don't know   // hello // world /* */
hello world /** abc * b/c /*
    hello ** // world
    *
    */
blah /* hi */ */ b
//
///hi
--- stap2
F(ngx_palloc) {
    if ($size < 0) {
        print_ubacktrace()
        exit()
    }
}
--- request
GET /t
--- response_body eval
qq{b = '"';  c = '"'
a = "h\\"/* */";
 i don't know   
hello world 
blah  */ b


}
--- no_error_log
[alert]
[error]



=== TEST 17: more patterns
--- config
    default_type text/html;
    replace_filter_max_buffered_size 1;
    location /t {
        #echo hello world hiya hiya world hello;
        replace_filter a A;
        replace_filter b B;
        replace_filter c C;
        replace_filter d D;
        replace_filter e E;
        replace_filter f F;
        replace_filter g G;
        replace_filter h H;
        replace_filter i I;
        replace_filter j J;
        replace_filter k K;
        replace_filter l L;
        replace_filter m M;
        replace_filter n N;
        replace_filter o O;
        replace_filter p P;
        replace_filter q Q;
        replace_filter r R;
        replace_filter s S;
        replace_filter t T;
        replace_filter u U;
        replace_filter v V;
        replace_filter w W;
        replace_filter x X;
        replace_filter y Y;
        replace_filter z Z;
    }
--- request
GET /t
--- user_files
>>> t
It'll be officially possible when the timer_by_lua directive is
implemented in ngx_lua :)

For now, people have been using some tricks to do something like that,
i.e., using detached long-running requests (by calling ngx.eof early).
See the related documentation for details:

--- response_body
IT'Ll BE OFfICiAllY PoSsible WHeN the tiMeR_by_lUa DirectiVe is
implemented in nGX_lua :)

For now, people have been using some tricKs to do something like that,
i.e., using detached long-running reQuests (by calling ngx.eof early).
See the related documentation for details:

--- stap2 eval: $::StapOutputChains
--- no_error_log
[alert]
[error]

