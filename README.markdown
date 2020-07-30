Description
===========

**testcookie-nginx-module** is a simple robot mitigation module using cookie based challenge/response.

Challenge cookies can be set using different methods:

*   "Set-Cookie" + 302/307 HTTP Location redirect
*   "Set-Cookie" + HTML meta refresh redirect
*   Custom template, JavaScript can be used here.

To prevent automatic parsing, challenge cookie value can be encrypted with AES-128 in CBC mode using custom/random key and iv, and then decrypted at client side with JavaScript.


Directives
==========

testcookie
----------
**syntax:** *testcookie (on|off|var);*

**default:** *off*

**context:** *http, server, location, if*

on - Enable module

off - Disable module

var - Don't intercept requests, only set module variables.


testcookie_name
---------------
**syntax:** *testcookie_name &lt;string&gt;*

**default:** *TCK*

**context:** *http, server, location*

Sets cookie name.

testcookie_domain
-----------------
**syntax:** *testcookie_domain &lt;string&gt;*

**default:** *none, set by browser*

**context:** *http, server, location*

Sets cookie domain.


testcookie_expires
------------------
**syntax:** *testcookie_expires &lt;string&gt;*

**default:** *31 Dec 2037 23:55:55 GMT*

**context:** *http, server, location*

Sets cookie expiration value.

testcookie_path
---------------
**syntax:** *testcookie_path &lt;string&gt;*

**default:** */*

**context:** *http, server, location*

Sets cookie path, useful if you plan to use different keys for locations.

testcookie_samesite
---------------
**syntax:** *testcookie_samesite &lt;string&gt;*

**default:** *None*

**context:** *http, server, location*

Sets cookie attribute, allows you to declare if your cookie should be restricted to a first-party or same-site context.
Default is None (Cookies will be sent in all contexts, i.e sending cross-origin is allowed.)
Accepts values: Lax, Strict, None.

testcookie_secret
-----------------
**syntax:** *testcookie_secret &lt;string&gt;*

**default:** *required configuration directive*

**context:** *http, server, location*

Secret string, used in challenge cookie computation, should be 32 bytes or more,
better to be long but static to prevent cookie reset for legitimate users every server restart.
If set to *"random"* - new secret will be generated every server restart, not recomended(all cookies with previous key will be invalid),

testcookie_session
------------------
**syntax:** *testcookie_session &lt;variable&gt;*

**default:** *required configuration directive*

**context:** *http, server, location*

Sets the challenge generation function input,
*   $remote_addr - clients IP address will be used as an user unique identifier
*   $remote_addr$http_user_agent - clients IP + User-Agent

testcookie_arg
--------------
**syntax:** *testcookie_arg &lt;string&gt;*

**default:** *none*

**context:** *http, server, location*

Sets GET parameter name, used for cookie setting attempts computation,

If not set - server will try to set cookie infinitely.

testcookie_max_attempts
-----------------------
**syntax:** *testcookie_max_attempts &lt;integer&gt;*

**default:** *5*

**context:** *http, server, location*

Sets maximum number of redirects before user will be sent to fallback URL, according to RFC1945 can't be more than 5.

If set to 0 - server will try to set cookie infinitely(actually, browser will show the error page).


testcookie_p3p
--------------
**syntax:** *testcookie_p3p &lt;string&gt;*

**default:** *none*

**context:** *http, server, location*

Sets P3P policy.

testcookie_fallback
-------------------
**syntax:** *testcookie_fallback &lt;script&gt;*

**default:** *none*

**context:** *http, server, location*

Sets the fallback URL, user will be redirected to after maximum number of attempts, specified by directive *testcookie_max_attempts* exceded.
Nginx scripting variables can be used here. If not set - client will get 403 after max attempts reached.

testcookie_whitelist
--------------------
**syntax:** *testcookie_whitelist &lt;network list&gt;*

**default:** *none*

**context:** *http, server*

Sets the networks for which the testing will not be used, add search engine networks here. Currently IPv4 CIDR only.

testcookie_pass
---------------
**syntax:** *testcookie_pass $variable;*

**default:** *none*

**context:** *http, server*

Sets the variable name to test if cookie check should be bypassed.
If variable value set to *1* during the request - cookie check will not be performed.
Can be used for more complex whitelisting.

testcookie_redirect_via_refresh
-------------------------------
**syntax:** *testcookie_redirect_via_refresh (on|off);*

**default:** *off*

**context:** *http, server, location*

Set cookie and redirect using HTTP meta refresh, required if *testcookie_refresh_template* used.

testcookie_refresh_template
---------------------------
**syntax:** *testcookie_refresh_template &lt;string&gt;*

**default:** *none*

**context:** *http, server, location*

Use custom html instead of simple HTTP meta refresh, you need to set cookie manually from the template
Available all the nginx variables and

    $testcookie_nexturl - URL the client should be redirected to, if max_attempts exceeded *testcookie_fallback* value will be here
    $testcookie_got - cookie value received from client, empty if no cookie or it does not match format
    $testcookie_set - correct cookie value we're expecting from client
    $testcookie_ok - user passed test (1 - passed, 0 - not passed) Note: changed from "yes"/"no" in v1.10

also, if testcookie_refresh_encrypt_cookie enabled there are three more variables:

    $testcookie_enc_key - encryption key (32 hex digits)
    $testcookie_enc_iv - encryption iv (32 hex digits)
    $testcookie_enc_sec - encrypted cookie value (32 hex digits)

testcookie_refresh_status
-------------------------
**syntax:** *testcookie_refresh_status &lt;code&gt;*

**default:** *200*

**context:** *http, server, location*

Use custom HTTP status code when serving html.


testcookie_deny_keepalive
-------------------------
**syntax:** *testcookie_deny_keepalive (on|off);*

**default:** *off*

**context:** *http, server, location*

Close connection just after setting the cookie, no reason to keep connections with bots.

testcookie_get_only
-------------------
**syntax:** *testcookie_get_only (on|off);*

**default:** *off*

**context:** *http, server, location*

Process only GET requests, POST requests will be bypassed.

testcookie_https_location
-------------------------
**syntax:** *testcookie_https_location (on|off);*

**default:** *off*

**context:** *http, server, location*

Redirect client to https protocol after setting the cookie, also affects *$testcookie_nexturl*, useful with 3dparty SSL offload.

testcookie_refresh_encrypt_cookie
---------------------------------
**syntax:** *testcookie_refresh_encrypt_cookie (on|off);*

**default:** *off*

**context:** *http, server, location*

Encrypt cookie variable, used with *testcookie_refresh_template* to force client-side decryption with AES-128 CBC.

testcookie_refresh_encrypt_cookie_key
-------------------------------------
**syntax:** *testcookie_refresh_encrypt_cookie_key &lt;32 hex digits|random&gt;*

**default:** *required directive if encryption enabled*

**context:** *http, server, location*

Sets encryption key.

Possible values:

    random - new key generated every nginx restart
    32 hex digits - static key, useful if you plan to obfuscate it deep in client-side javascript.

testcookie_refresh_encrypt_iv
-----------------------------
**syntax:** *testcookie_refresh_encrypt_iv &lt;32 hex digits|random|random2&gt;*

**default:** *random*

**context:** *http, server, location*

Sets encryption iv.

Possible values:
    random - new iv generated for every client request
    random2 - new iv generated for every nginx restart
    32 hex digits - static iv, useful if you plan to obfuscate it deep in client-side javascript

testcookie_internal
-------------------
**syntax:** *testcookie_internal (on|off);*

**default:** *off*

**context:** *http, server, location*

Enable testcookie check for internal redirects (disabled by default for optimization purposes!), useful for this type of configs:

    rewrite ^/(.*)$ /index.php?$1 last;

testcookie_httponly_flag
------------------------
**syntax:** *testcookie_httponly_flag (on|off);*

**default:** *off*

**context:** *http, server, location*

Enable HttpOnly flag for cookie.

testcookie_secure_flag
------------------------
**syntax:** *testcookie_secure_flag (on|off|$variable);*

**default:** *on*

**context:** *http, server, location*

Enable Secure flag for cookie.
Any variable value except "on" interpreted as False.

testcookie_port_in_redirect
---------------------------
**syntax:** *testcookie_port_in_redirect (on|off);*

**default:** *off*

**context:** *http, server, location*

Expose port in redirect.


Installation
============

Grab the nginx source code from [nginx.org](http://nginx.org/), for example, the version 1.1.15 (see nginx compatibility), and then build the source with this module:

    wget 'http://nginx.org/download/nginx-1.1.15.tar.gz'
    tar -xzvf nginx-1.1.15.tar.gz
    cd nginx-1.1.15/
    ./configure --add-module=/path/to/testcookie-nginx-module

    make
    make install

If you use nginx >= 1.9.11 you can compile Dynamic module.

    wget 'http://nginx.org/download/nginx-1.9.11.tar.gz'
    tar -xzvf nginx-1.9.11.tar.gz
    cd nginx-1.9.11/
    ./configure --add-dynamic-module=/path/to/testcookie-nginx-module

    make
    make install

Then load "ngx_http_testcookie_access_module.so" using "load_module" directive.

For using client-side cookie decryption, you need to manually grab [SlowAES](http://code.google.com/p/slowaes/) JavaScript AES implementation,
**patch it(utils/aes.patch)** and put it to document root.

Compatibility
=============

Module was tested with nginx 1.1+, but should work with 1.0+.

Example configuration
=====================

    http {
        #default config, module disabled
        testcookie off;

        #setting cookie name
        testcookie_name BPC;

        #setting secret
        testcookie_secret keepmesecret;

        #setting session key
        testcookie_session $remote_addr;

        #setting argument name
        testcookie_arg ckattempt;

        #setting maximum number of cookie setting attempts
        testcookie_max_attempts 3;

        #setting p3p policy
        testcookie_p3p 'CP="CUR ADM OUR NOR STA NID", policyref="/w3c/p3p.xml"';

        #setting fallback url
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;

        #configuring whitelist
        testcookie_whitelist {
            8.8.8.8/32;
        }


        #setting redirect via html code
        testcookie_redirect_via_refresh on;

        #enable encryption
        testcookie_refresh_encrypt_cookie on;

        #setting encryption key
        testcookie_refresh_encrypt_cookie_key deadbeefdeadbeefdeadbeefdeadbeef;

        #setting encryption iv
        testcookie_refresh_encrypt_cookie_iv deadbeefdeadbeefdeadbeefdeadbeef;

        #setting response template
        testcookie_refresh_template '<html><body>setting cookie...<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var a=toNumbers("$testcookie_enc_key"),b=toNumbers("$testcookie_enc_iv"),c=toNumbers("$testcookie_enc_set");document.cookie="BPC="+toHex(slowAES.decrypt(c,2,a,b))+"; expires=Thu, 31-Dec-37 23:55:55 GMT; path=/";location.href="$testcookie_nexturl";</script></body></html>';

        server {
            listen 80;
            server_name test.com;


            location = /aes.min.js {
                gzip  on;
                gzip_min_length 1000;
                gzip_types      text/plain;
                root /var/www/public_html;
            }

            location = /w3c/p3p.xml {
                root /var/www/public_html;
            }

            location / {
                #enable module for specific location
                testcookie on;
                proxy_set_header   Host             $host;
                proxy_set_header   X-Real-IP        $remote_addr;
                proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
                proxy_pass http://127.0.0.1:80;
            }
        }
    }

See more cases in "docs" directory of the project.

Test suite
===========

This module comes with a Perl-driven test suite. Thanks to the [Test::Nginx](http://search.cpan.org/perldoc?Test::Nginx) module in the Perl world.

Sources
=======

Available on github at [kyprizel/testcookie-nginx-module](http://github.com/kyprizel/testcookie-nginx-module).

TODO
====

*   Code review
*   Statistics (?)

Bugs
====

Feel free to report bugs and send patches to kyprizel@gmail.com
or using [github's issue tracker](http://github.com/kyprizel/testcookie-nginx-module/issues).

Support the project
===================

    Send your donations to 1FHmPTP6aDBAzVtM7Pe7Y69zqhjPRx847s


Copyright & License
===================

Copyright (C) 2011-2017 Eldar Zaitov (kyprizel@gmail.com).

All rights reserved.

This module is licenced under the terms of BSD license.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    *   Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    *   Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    *   Neither the name of the authors nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
