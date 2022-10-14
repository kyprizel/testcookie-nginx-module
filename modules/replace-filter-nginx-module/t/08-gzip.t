# vim:set ft= ts=4 sw=4 et fdm=marker:

use lib 'lib';
use Test::Nginx::Socket;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

no_shuffle();

plan tests => repeat_each() * (blocks() * 3);

run_tests();

__DATA__

=== TEST 1: once patterns
--- config
    default_type text/html;
    replace_filter_max_buffered_size 0;
    location /t {
        content_by_lua '
            ngx.header.content_encoding = "gzip"
            ngx.say("hello world world hello");
        ';
        replace_filter hello "[$&]";
        replace_filter world "<$&>";
    }
--- request
GET /t
--- response_body
hello world world hello
--- no_error_log
[error]

