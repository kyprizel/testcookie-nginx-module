# ngx_http_captcha_module
<h1>说明：</h1>
<br>此nginx模块可直接生成验证码和验证验证码，可在nginx配置中自定义验证码大小、长度、字体、过期时间等。此项目无需版权，可自由下载使用或二次开发。</br>
<p></p>
<h1>安装方法：</h1>
<br>1. $ cp ngx_http_captcha_module.c /usr/local/src/nginx-1.14.0/src/http/modules/</br>
<br>2. cd /usr/local/src/nginx-1.14.0</br>
<br>3. $ vim auto/modules</br>
<br>添加代码</br>
<pre><code>
if :; then
    ngx_module_name=ngx_http_captcha_module
    ngx_module_incs=
    ngx_module_deps=
    ngx_module_srcs=src/http/modules/ngx_http_captcha_module.c
    ngx_module_libs=
    ngx_module_link=YES

    . auto/module
fi
</code></pre>
<br>4. $ ./configure --with-debug</br>
<br>5. $ vim objs/Makefile</br>

<br>找到</br>
<pre><code>
objs/src/http/modules/ngx_http_captcha_module.o:        $(CORE_DEPS) $(HTTP_DEPS) \
        src/http/modules/ngx_http_captcha_module.c
        $(CC) -c -g $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
                -o objs/src/http/modules/ngx_http_captcha_module.o \
                src/http/modules/ngx_http_captcha_module.c
</code></pre>

<br>改为</br>
<pre><code>
objs/src/http/modules/ngx_http_captcha_module.o:        $(CORE_DEPS) $(HTTP_DEPS) \
        src/http/modules/ngx_http_captcha_module.c
        $(CC) -c -g $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
                -I /usr/include -I /usr/local/include \
                -L /usr/lib/ -L /usr/local/lib/ -lgd -lhiredis \
                -o objs/src/http/modules/ngx_http_captcha_module.o \
                src/http/modules/ngx_http_captcha_module.c
</code></pre>
<br>找到</br>
<pre><code>
-ldl -lrt -lpthread -lcrypt -lpcre -lz \
</code></pre>
<br>改为</br>
<pre><code>
-ldl -lrt -lpthread -lcrypt -lpcre -lz -lgd -lhiredis \
</code></pre>
<br>6. $ make && make install</br>

<p></p>
<h1>nginx配置</h1>
<pre><code>
    location /captcha_img {
        captcha_redis_conf 127.0.0.1 6379;    #redis配置，默认127.0.0.1 6379
        captcha_init;                         #验证码初始化
        captcha_width 130;                    #验证码宽度，默认130像素
        captcha_height 30;                    #验证码高度，默认30像素
        captcha_length 4;                     #验证码长度，默认4，最大长度6
        captcha_font /data/font/elephant.ttf; #字体库
        captcha_expire 3600;                  #过期时间， 默认3600秒
        captcha_output;                       #输出图像
    }

    location /captcha_auth {
        captcha_redis_conf 127.0.0.1 6379;    #redis配置，默认127.0.0.1 6379
        captcha_auth;                         #验证
    }
</code></pre>

<br>重启nginx
<br>访问http://xxx/captcha_img显示验证码图片</br>
<br>访问http://xxx/captcha_auth?captcha_code=1234</br>
<br>captcha_code=1234为用户输入的验证码参数，用get请求方式</br>

<p></p>
<h1>联系方式：</h1>
<br>欢迎发邮件962404383@qq.com，一起学习交流</br>