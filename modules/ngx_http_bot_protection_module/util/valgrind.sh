#!/bin/sh


export TEST_NGINX_PORT=30001
export TEST_NGINX_USE_VALGRIND=1
prove -v -r t
