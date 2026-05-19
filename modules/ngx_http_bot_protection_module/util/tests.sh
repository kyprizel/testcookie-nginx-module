#!/bin/sh


export TEST_NGINX_PORT=30001
prove -v -r t
