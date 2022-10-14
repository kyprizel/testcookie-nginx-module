Nginx Input Validation Module
    *Note: this module is not distributed with the Nginx source.
    Installation instructions can be found below.*

  Description
    Input Validation is a request inspection module which can do both regular
    expression and fixed string on request bodies. 
    It inspect the request parameters and block the abnormal requests bases on rules.


Usage Example:
      location /post.php {
        input_validation on;
        input_validation_arg "username" "^[a-zA-Z0-9_]" "10" block;
        input_validation_arg "password" "^[A-Za-z0-9!@#$%^&*()_+]" "15" block;
        input_validation_arg "phone" "^[+0-9]" "15" block ;
        input_validation_arg "address" "^[A-Za-z0-9]" "40" block;
        input_validation_max_arg 30;
        error_log  logs/error.log  debug;
        root   html;
        index  index.html index.htm;
        proxy_pass http://127.0.0.1:8080/post.php;
        }
		
  Directives
    *   input_validation
		context: *http, server, location*
		Value: on|off   ( Enable/Disable Module) 
		

    *   input_validation_arg
		context: *http, server, location*
		Arguments Format:   "Variable Name"  "^[Regex]" "Variable Maximum Length" "Action"
		where:
				"Variable Name" to argument name in request body
				"^[Regex]" to Regular Expression
				"Variable Maximum Length" Variable Maximum Length , Integer
				"Action" Action if the attack detection , "block" immediately block the request , "learn" for IronFox profiler

	*   input_validation_max_arg
		context: *http, server, location*
		Define the maximum arguments count to blocking the hashdos attack. default is a 800.  


  Installation
    To install, get the source with subversion:

    git clone
    https://github.com/irontoolki/IronFox/tree/master/ironfox/ngx_Input_Validation_module

    and then compile Nginx with the following option:

    ./configure --add-module=/path/to/module

  Known issue
    *  


  Reporting a bug
    Questions/patches may be directed to khalegh Salehi, khaleghsalehi@gmail.com

========================================================================
Copyright & License
    The code base is borrowed directly from the hashdos at https://github.com/54chen/nginx-http-hashdos-module .
	This part of code is copyrighted by Xiaomi Corp.
	
    Copyright (c) 2016 , Khalegh Salehi , khaleghsalehi@gmail.com , IronFox.org.


This module is licensed under the terms of the BSD license.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  
  
