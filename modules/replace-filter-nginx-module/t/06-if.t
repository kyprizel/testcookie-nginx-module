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

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: local if hit
--- config
    location /t {
        default_type text/plain;
        echo abcabcabde;

        if ($arg_disable = "") {
            replace_filter_types text/plain;
            replace_filter_max_buffered_size 0;
            replace_filter abcabd X;
        }
    }
--- request
GET /t
--- response_body
abcXe
--- no_error_log
[alert]
[error]



=== TEST 2: local if miss
--- config
    replace_filter_max_buffered_size 0;
    location /t {
        default_type text/plain;
        echo abcabcabde;

        if ($arg_disable = "") {
            replace_filter_types text/plain;
            replace_filter_max_buffered_size 0;
            replace_filter abcabd X;
        }
    }
--- request
GET /t?disable=1
--- response_body
abcabcabde
--- no_error_log
[alert]
[error]

