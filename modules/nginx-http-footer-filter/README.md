# HTTP Footer filter module for Nginx

## Introduction

This is a module that is distributed with
[tengine](http://tengine.taobao.org) which is a distribution of
[Nginx](http://nginx.org) that is used by the e-commerce/auction site
[Taobao.com](http://en.wikipedia.org/wiki/Taobao). This distribution
contains some modules that are new on the Nginx scene. The
`ngx_http_footer_filter` module is one of them.

This module implements a body filter that adds a given string to the
page footer.

You might say that it provides a particular case of the
[http sub module](http://wiki.nginx.org/HttpSubModule) in the sense
that it adds something to the footer. You can do the same using the
`http sub module` but using the footer filter should be faster since
there's no string matching done on the request body.

## Configuration example

    location / {
        ## Using the $date_gmt variable from the SSI module (prints a
        ## UNIX timestamp).
        footer "<!-- $date_gmt -->";
        index index.html;
    }

    location ^~ /assets/css {
        ## Add CSS to the MIME types to be added a footer.
        footer_types text/css; 
    
        footer "/* host: $server_name - $date_local */";
    }

## Module directives

**footer** `string`

**default:** ``

**context:** `http, server, location`

It defines the string to be printed at the footer of the request
body. This string can have variables embedded.

<br/>
<br/>

**footer_types** `MIME types`

**default:** `footer_types: text/html`

**context:** `http, server, location`

Defines the [MIME types](http://en.wikipedia.org/wiki/MIME_type) of
the files where the footer will be included.

## Installation

 1. Clone the git repo.
    
        git clone  git://github.com/taobao/nginx-http-footer-filter.git

 2. Add the module to the build configuration by adding
    `--add-module=/path/to/nginx-http-footer-filter`.

 3. Build the nginx binary.
 
 4. Install the nginx binary.
 
 5. Configure contexts where footer filter is enabled.

 6. Done.

## Tagging releases 

I'm tagging each release in synch with the
[Tengine](http://tengine.taobao.org) releases.
 
## Other tengine modules on Github

 + [http concat](https://github.com/taobao/nginx-http-concat):
   allows to concatenate a given set of files and ship a single
   response from the server. It's particularly useful for **aggregating**
   CSS and Javascript files.

 + [http slice](https://github.com/taobao/nginx-http-slice): allows
   to serve a file by slices. A sort of reverse byte-range. Useful for
   serving large files while not hogging the network. 

## Original documentation

The
[original documentation](http://tengine.taobao.org/document_cn/http_footer_filter_cn.html)
in Chinese. Note that the examples given therein rely on
**non-standard** Nginx
[variables](http://tengine.taobao.org/document_cn/variables_cn.html)
that are not
[available](http://nginx.org/en/docs/http/ngx_http_core_module.html#variables)
on the official Nginx source but only on [tengine](http://tengine.taobao.org).

## License

Copyright (C) 2010-2012 Alibaba Group Holding Limited

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
 
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
    
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
