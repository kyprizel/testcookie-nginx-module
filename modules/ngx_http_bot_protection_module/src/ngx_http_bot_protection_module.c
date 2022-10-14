/*
  Innovera Technology; https://innovera.ir
  IronFox project, Version 0.1.0

  Copyright (C) 2016-2020 Khalegh Salehi (khaleghsalehi@gmail.com).
  Copyright (C) 2011-2018 Eldar Zaitov (eldar@kyprizel.net).

  All rights reserved.
  This module is licenced under the terms of BSD license.

*/


//todo obfuscate all string like token= kooki= javascripts etc ..

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include "ngx_http_bot_protection_module.h"


unsigned long count_success_req;
unsigned long count_failed_req;


typedef struct {
    ngx_uint_t enable;

    ngx_uint_t anomaly_detection;

    ngx_str_t name;
    ngx_str_t token;
    ngx_str_t domain;
    ngx_str_t path;
    ngx_str_t p3p;

    time_t expires;

    ngx_str_t arg;
    ngx_str_t secret;
    ngx_http_complex_value_t session_key;

    ngx_int_t max_attempts;

    ngx_radix_tree_t *whitelist;
#if (NGX_HAVE_INET6)
    ngx_radix_tree_t *whitelist6;
#endif

    ngx_str_t fallback;
    ngx_array_t *fallback_lengths;
    ngx_array_t *fallback_values;

    ngx_flag_t redirect_via_refresh;
    ngx_str_t refresh_template;
    ngx_array_t *refresh_template_lengths;
    ngx_array_t *refresh_template_values;
    ngx_uint_t refresh_status;

#ifdef PROBE_COOKIE_ENCRYPTION
    ngx_flag_t refresh_encrypt_cookie;
    u_char *refresh_encrypt_cookie_key;
    u_char *refresh_encrypt_cookie_iv;
#endif

    ngx_flag_t redirect_to_https;
    ngx_flag_t get_only;
    ngx_flag_t deny_keepalive;
    ngx_flag_t internal;
    ngx_flag_t httponly_flag;
    ngx_flag_t port_in_redirect;
    ngx_http_complex_value_t *secure_flag;
    ngx_http_complex_value_t *pass_var;
} ngx_http_bot_protection_conf_t;

typedef struct {
    u_char *uid_set;
    u_char *uid_got;
#ifdef PROBE_COOKIE_ENCRYPTION
    u_char *encrypt_salt;
    u_char *encrypt_key;
    u_char *encrypt_iv;
#endif
    u_short ok;
    ngx_str_t cookie;
} ngx_http_bot_protection_ctx_t;

static ngx_conf_enum_t ngx_http_bot_protection_state[] = {
        {ngx_string("off"), BOT_PROTECTION_OFF},
        {ngx_string("on"),  BOT_PROTECTION_ON},
        {ngx_string("var"), BOT_PROTECTION_VARIABLE},
        {ngx_null_string, 0}
};
static ngx_conf_enum_t ngx_http_bot_protection_anomaly_detection_state[] = {
        {ngx_string("off"), ANOMALY_DETECTION_OFF},
        {ngx_string("on"),  ANOMALY_DETECTION_ON},
        {ngx_null_string, 0}
};




static ngx_int_t ngx_http_send_refresh(ngx_http_request_t *r, ngx_http_bot_protection_conf_t *conf);

static ngx_int_t ngx_http_send_custom_refresh(ngx_http_request_t *r, ngx_http_bot_protection_conf_t *conf);

static ngx_int_t ngx_http_bot_protection_handler(ngx_http_request_t *r);

static ngx_http_bot_protection_ctx_t *ngx_http_bot_protection_get_uid(ngx_http_request_t *r,
                                                                      ngx_http_bot_protection_conf_t *conf);

static ngx_int_t ngx_http_bot_protection_set_uid(ngx_http_request_t *r,
                                                 ngx_http_bot_protection_ctx_t *ctx,
                                                 ngx_http_bot_protection_conf_t *conf);

static ngx_int_t ngx_http_bot_protection_timestamp_variable(ngx_http_request_t *r,
                                                            ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_bot_protection_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_bot_protection_init(ngx_conf_t *cf);

static void *ngx_http_bot_protection_create_conf(ngx_conf_t *cf);

static char *ngx_http_bot_protection_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_bot_protection_domain(ngx_conf_t *cf, void *post, void *data);

static char *ngx_http_bot_protection_path(ngx_conf_t *cf, void *post, void *data);

static char *ngx_http_bot_protection_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_bot_protection_p3p(ngx_conf_t *cf, void *post, void *data);

static char *ngx_http_bot_protection_secret(ngx_conf_t *cf, void *post, void *data);

static char *ngx_http_bot_protection_max_attempts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_bot_protection_whitelist_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_bot_protection_whitelist(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);

static char *ngx_http_bot_protection_fallback_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_bot_protection_session_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_bot_protection_refresh_template_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

u_char *ngx_hextobin(u_char *dst, u_char *src, size_t len);

int ngx_ishex(u_char *src, size_t len);

static char *ngx_http_bot_protection_refresh_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_bot_protection_nocache(ngx_http_request_t *r);


#ifdef PROBE_COOKIE_ENCRYPTION

static char *ngx_http_bot_protection_set_encryption_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_bot_protection_set_encryption_iv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif

static u_char expires[] = "; expires=Wed, 25-Jan-25 12:00:00 GMT";

static u_char ngx_http_msie_refresh_head[] =
        "<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";

static u_char ngx_http_msie_refresh_tail[] =
        "\"></head><body></body></html>" CRLF;


static ngx_conf_post_handler_pt ngx_http_bot_protection_domain_p = ngx_http_bot_protection_domain;
static ngx_conf_post_handler_pt ngx_http_bot_protection_path_p = ngx_http_bot_protection_path;
static ngx_conf_post_handler_pt ngx_http_bot_protection_p3p_p = ngx_http_bot_protection_p3p;
static ngx_conf_post_handler_pt ngx_http_bot_protection_secret_p = ngx_http_bot_protection_secret;

static ngx_command_t ngx_http_bot_protection_commands[] = {

        {ngx_string("bot_protection_manager"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_SIF_CONF
         | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_enum_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, enable),
         ngx_http_bot_protection_state},

        {ngx_string("bot_protection_anomaly_detection"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_SIF_CONF
         | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_enum_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, anomaly_detection),
         ngx_http_bot_protection_anomaly_detection_state},

        {ngx_string("bot_protection_cookie_name"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_str_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, name),
         NULL},
        {ngx_string("bot_protection_token"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_str_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, token),
         NULL},

        {ngx_string("bot_protection_domain"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_str_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, domain),
         &ngx_http_bot_protection_domain_p},

        {ngx_string("bot_protection_path"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_str_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, path),
         &ngx_http_bot_protection_path_p},

        {ngx_string("bot_protection_expires"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_bot_protection_expires,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        {ngx_string("bot_protection_p3p"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_str_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, p3p),
         &ngx_http_bot_protection_p3p_p},

        {ngx_string("bot_protection_arg"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_str_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, arg),
         NULL},

        {ngx_string("bot_protection_session"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_bot_protection_session_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        {ngx_string("bot_protection_secret"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_str_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, secret),
         &ngx_http_bot_protection_secret_p},

        {ngx_string("bot_protection_fallback"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_bot_protection_fallback_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, fallback),
         NULL},

        {ngx_string("bot_protection_max_attempts"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_bot_protection_max_attempts,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        {ngx_string("bot_protection_whitelist"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
         ngx_http_bot_protection_whitelist_block,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, whitelist),
         NULL},

        {ngx_string("bot_protection_https_location"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, redirect_to_https),
         NULL},

        {ngx_string("bot_protection_get_only"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, get_only),
         NULL},

        {ngx_string("bot_protection_redirect_via_refresh"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, redirect_via_refresh),
         NULL},

        {ngx_string("bot_protection_refresh_template"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_bot_protection_refresh_template_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        {ngx_string("bot_protection_refresh_status"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_bot_protection_refresh_status,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        {ngx_string("bot_protection_deny_keepalive"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, deny_keepalive),
         NULL},

        {ngx_string("bot_protection_internal"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, internal),
         NULL},

#ifdef PROBE_COOKIE_ENCRYPTION

        {ngx_string("bot_protection_refresh_encrypt_cookie"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, refresh_encrypt_cookie),
         NULL},

        {ngx_string("bot_protection_refresh_encrypt_cookie_key"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_bot_protection_set_encryption_key,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        {ngx_string("bot_protection_refresh_encrypt_cookie_iv"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_bot_protection_set_encryption_iv,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

#endif

        {ngx_string("bot_protection_httponly_flag"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, httponly_flag),
         NULL},

        {ngx_string("bot_protection_secure_flag"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_set_complex_value_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, secure_flag),
         NULL},

        {ngx_string("bot_protection_pass"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_http_set_complex_value_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, pass_var),
         NULL},

        {ngx_string("bot_protection_port_in_redirect"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_bot_protection_conf_t, port_in_redirect),
         NULL},

        ngx_null_command
};




static ngx_http_module_t ngx_http_bot_protection_module_ctx = {
        ngx_http_bot_protection_add_variables,                /* preconfiguration */
        ngx_http_bot_protection_init,                         /* postconfiguration */

        NULL,                                  /* create main configuration */
        NULL,                                    /* init main configuration */

        NULL,                                   /* create server configuration */
        NULL,                                   /* merge server configuration */

        ngx_http_bot_protection_create_conf,                 /* create location configration */
        ngx_http_bot_protection_merge_conf                   /* merge location configration */
};


ngx_module_t ngx_http_bot_protection_module = {
        NGX_MODULE_V1,
        &ngx_http_bot_protection_module_ctx,               /* module context */
        ngx_http_bot_protection_commands,                  /* module directives */
        NGX_HTTP_MODULE,                                   /* module type */
        NULL,                                    /* init master */
        NULL,                                   /* init module */
        NULL,                                   /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                   /* exit master */
        NGX_MODULE_V1_PADDING
};


static ngx_str_t ngx_http_bot_protection_got = ngx_string("bot_protection_got");
static ngx_str_t ngx_http_bot_protection_set = ngx_string("bot_protection_set");
static ngx_str_t ngx_http_bot_protection_ok = ngx_string("bot_protection_ok");
static ngx_str_t ngx_http_bot_protection_nexturl = ngx_string("bot_protection_nexturl");
static ngx_str_t ngx_http_bot_protection_timestamp = ngx_string("bot_protection_timestamp");

#ifdef PROBE_COOKIE_ENCRYPTION
static ngx_str_t ngx_http_bot_protection_enc_salt = ngx_string("bot_protection_enc_salt");
static ngx_str_t ngx_http_bot_protection_enc_set = ngx_string("bot_protection_enc_set");
static ngx_str_t ngx_http_bot_protection_enc_iv = ngx_string("bot_protection_enc_iv");
static ngx_str_t ngx_http_bot_protection_enc_key = ngx_string("bot_protection_enc_key");
#endif

static ngx_int_t
ngx_http_send_refresh(ngx_http_request_t *r, ngx_http_bot_protection_conf_t *conf) {
    u_char *p, *location;
    size_t len, size;
    uintptr_t escape;
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;

    len = r->headers_out.location->value.len;
    location = r->headers_out.location->value.data;

    escape = 2 * ngx_escape_uri(NULL, location, len, NGX_ESCAPE_REFRESH);

    size = sizeof(ngx_http_msie_refresh_head) - 1
           + escape + len
           + sizeof(ngx_http_msie_refresh_tail) - 1;

    r->err_status = conf->refresh_status;

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    r->headers_out.location->hash = 0;
    r->headers_out.location = NULL;

    r->headers_out.content_length_n = size;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);
    ngx_http_bot_protection_nocache(r);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR) {
        return rc;
    }

    if (r->header_only) {
        ngx_http_finalize_request(r, 0);
        return NGX_DONE;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(b->pos, ngx_http_msie_refresh_head,
                   sizeof(ngx_http_msie_refresh_head) - 1);

    if (escape == 0) {
        p = ngx_cpymem(p, location, len);
    } else {
        p = (u_char *) ngx_escape_uri(p, location, len, NGX_ESCAPE_REFRESH);
    }

    b->last = ngx_cpymem(p, ngx_http_msie_refresh_tail,
                         sizeof(ngx_http_msie_refresh_tail) - 1);

    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);
    return NGX_DONE;
}

static ngx_int_t
ngx_http_send_custom_refresh(ngx_http_request_t *r, ngx_http_bot_protection_conf_t *conf) {
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_str_t compiled_refresh_template;

    r->err_status = conf->refresh_status;

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    if (conf->refresh_template_lengths != NULL && conf->refresh_template_values != NULL) {
        if (ngx_http_script_run(r, &compiled_refresh_template, conf->refresh_template_lengths->elts,
                                0, conf->refresh_template_values->elts) == NULL) {
            return NGX_ERROR;
        }
    } else {
        compiled_refresh_template.data = conf->refresh_template.data;
        compiled_refresh_template.len = conf->refresh_template.len;
    }

    r->headers_out.location->hash = 0;
    r->headers_out.location = NULL;

    r->headers_out.content_length_n = compiled_refresh_template.len;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);
    ngx_http_bot_protection_nocache(r);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR) {
        return rc;
    }

    if (r->header_only) {
        ngx_http_finalize_request(r, 0);
        return NGX_DONE;
    }

    b = ngx_create_temp_buf(r->pool, compiled_refresh_template.len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->start, compiled_refresh_template.data,
                         compiled_refresh_template.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection compiled refresh template with len: \"%d\"", compiled_refresh_template.len);

    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);
    return NGX_DONE;
}

static ngx_int_t
ngx_http_bot_protection_handler(ngx_http_request_t *r) {
    ngx_http_bot_protection_ctx_t *ctx;
    ngx_http_bot_protection_conf_t *conf;
    ngx_str_t *args, *look;
    ngx_uint_t i, j, k, l, uri_len;
    ngx_int_t attempt;
    ngx_int_t rc;
    u_char *buf, *p;
    size_t len;
    u_short sc;
    ngx_table_elt_t *location;
    ngx_str_t compiled_fallback;
    ngx_str_t pass_mode;
    ngx_uint_t port = 80; /* make gcc happy */
    struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6 *sin6;
#endif

    if (r != r->main) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                   r->connection->log,
                   0,
                   "bot_protection incoming request type: %d",
                   r->internal);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_bot_protection_module);
    if (!conf || conf->enable == BOT_PROTECTION_OFF) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ngx_http_bot_protection_handler");

    if (r->internal && !conf->internal) {
        return NGX_DECLINED;
    }

    if (conf->pass_var != NULL
        && ngx_http_complex_value(r, conf->pass_var, &pass_mode) == NGX_OK
        && pass_mode.len == 1
        && pass_mode.data[0] == '1') {
        return NGX_DECLINED;
    }


    ctx = ngx_http_bot_protection_get_uid(r, conf);
    if (ctx == NULL) {
//        return NGX_DECLINED;
        return NGX_HTTP_FORBIDDEN;
    }

    if (conf->enable == BOT_PROTECTION_VARIABLE) {
        return NGX_DECLINED;
    }

    if (conf->get_only
        && (r->method != NGX_HTTP_GET
            && r->method != NGX_HTTP_HEAD)) {
        return NGX_DECLINED;
    }

    if (conf->deny_keepalive) {
        r->keepalive = 0;
    }


    if (ctx->ok == 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bot_protection user passed test");
        count_success_req++;
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "bot_protection req count success: %l", count_success_req);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bot_protection req count success: %l", count_success_req);
        return NGX_DECLINED;
    } else {
        count_failed_req++;
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "bot_protection req count failed: %l", count_failed_req);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bot_protection req count failed: %l", count_failed_req);
    }

    args = &r->args;
    look = &conf->arg;
    i = j = k = l = 0;
    attempt = 0;
    sc = 0;
    uri_len = 0;

    if (look->len > 0) {
        if (args->len > 0) {
            for (i = 0; i <= args->len; i++) {
                if ((i == args->len) || (args->data[i] == '&')) {
                    if (j > 1) {
                        k = j;
                        l = i;
                    }
                    j = 0;
                } else if ((j == 0) && (i < args->len - look->len)) {
                    if ((ngx_strncmp(args->data + i, look->data, look->len) == 0)
                        && (args->data[i + look->len] == '=')) {
                        j = i + look->len + 1;
                        i = j - 1;
                    } else {
                        j = 1;
                    }
                }
            }
            if (l > k) {
                attempt = ngx_atoi(args->data + k, 1);
            }
        }

        if (conf->max_attempts > 0 && attempt >= conf->max_attempts) {
            r->keepalive = 0;
            if (conf->fallback.len == 0) {
                return NGX_HTTP_FORBIDDEN;
            }
            if (conf->fallback_lengths != NULL && conf->fallback_values != NULL) {
                if (ngx_http_script_run(r, &compiled_fallback, conf->fallback_lengths->elts,
                                        0, conf->fallback_values->elts) == NULL) {
                    return NGX_ERROR;
                }
                buf = compiled_fallback.data;
                len = compiled_fallback.len;
            } else {
                buf = conf->fallback.data;
                len = conf->fallback.len;
            }
            goto redirect;
        }
    }

    len = 0;
    if (r->headers_in.server.len > 0) {
        len = sizeof("http://") - 1 + r->headers_in.server.len;
#if (NGX_HTTP_SSL)
        if (r->connection->ssl || conf->redirect_to_https) {
            /* http:// -> https:// */
            len += 1;
        }
#endif
        /* XXX: this looks awful :( */
        if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        switch (r->connection->local_sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) r->connection->local_sockaddr;
                port = ntohs(sin6->sin6_port);
                break;
#endif
            default: /* AF_INET */
                sin = (struct sockaddr_in *) r->connection->local_sockaddr;
                port = ntohs(sin->sin_port);
                break;
        }
        if (port > 0 && port < 65535 && conf->port_in_redirect) {
            len += sizeof(":65535") - 1;
        }
    }

    if (r->unparsed_uri.len == 0) {
        len += 1;
    } else {
        p = r->unparsed_uri.data;
        for (uri_len = 0; uri_len < r->unparsed_uri.len; uri_len++) {
            if (*p == '?') {
                break;
            }
            p++;
        }
        len += uri_len;
    }
    if (look->len > 0) {
        if (args->len == 0) {
            sc = 1;
            len += look->len + sizeof("?=1") - 1;
        } else {
            if (l == k) {
                if (k == l && l == args->len) {
                    sc = 2;
                    len += args->len + sizeof("?1") - 1;
                } else {
                    sc = 3;
                    len += look->len + args->len + sizeof("?=1&") - 1;
                }
            } else {
                sc = 4;
                len += args->len + sizeof("?") - 1;
            }
        }
    } else {
        if (args->len > 0) {
            len += args->len + sizeof("?") - 1;
        }
    }

    buf = (u_char *) ngx_pcalloc(r->pool, len + 1);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = (u_char *) buf;

    if (r->headers_in.server.len > 0) {
#if (NGX_HTTP_SSL)
        if (r->connection->ssl || conf->redirect_to_https) {
            p = ngx_copy(p, "https://", sizeof("https://") - 1);
            p = ngx_copy(p, r->headers_in.server.data, r->headers_in.server.len);
        } else {
            p = ngx_copy(p, "http://", sizeof("http://") - 1);
            p = ngx_copy(p, r->headers_in.server.data, r->headers_in.server.len);
        }
#else
        p = ngx_copy(p, "http://", sizeof("http://") - 1);
        p = ngx_copy(p, r->headers_in.server.data, r->headers_in.server.len);
#endif

        if (port > 0 && port < 65535 && conf->port_in_redirect) {
            len -= sizeof(":65535") - 1;
            len += ngx_sprintf(p, ":%ui", port) - p;
            p = ngx_sprintf(p, ":%ui", port);
        }
    }

    if (r->unparsed_uri.len == 0) {
        (*p++) = '/';
    } else {
        p = ngx_copy(p, r->unparsed_uri.data, uri_len);
    }


    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection case%d", sc);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection l: %d", l);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection k: %d", k);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection attempts: %d\n", attempt);


    if (look->len > 0) {
        (*p++) = '?';
        switch (sc) {
            case 1:
                p = ngx_sprintf(p, "%V=1", look);
                break;
            case 2:
                p = ngx_sprintf(p, "%V1", args);
                break;
            case 3:
                p = ngx_sprintf(p, "%V&%V=1", args, look);
                break;
            case 4:
                attempt++;
                p = ngx_copy(p, args->data, k);
                p = ngx_sprintf(p, "%d", attempt);
                p = ngx_copy(p, args->data + l, args->len - l);
                break;
            default:
                break;
        }
    } else {
        if (args->len > 0) {
            (*p++) = '?';
            p = ngx_sprintf(p, "%V", args);
        }
    }

    rc = ngx_http_bot_protection_set_uid(r, ctx, conf);
    if (rc != NGX_OK) {
        return rc;
    }

    redirect:


    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection buf %s len: %d", buf, len);

    if (r->http_version < NGX_HTTP_VERSION_11) {
        r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
        rc = NGX_HTTP_MOVED_TEMPORARILY;
    } else {
        r->headers_out.status = NGX_HTTP_TEMPORARY_REDIRECT;
        rc = NGX_HTTP_TEMPORARY_REDIRECT;
    }
    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        return NGX_ERROR;
    }

    location->hash = 1;
    location->key.len = sizeof("Location") - 1;
    location->key.data = (u_char *) "Location";
    location->value.len = len;
    location->value.data = buf;

    r->headers_out.location = location;

    ngx_http_clear_accept_ranges(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_content_length(r);
    ngx_http_clear_etag(r);

    if (conf->redirect_via_refresh) {
        if (conf->refresh_template.len == 0) {
            return ngx_http_send_refresh(r, conf);
        } else {
            return ngx_http_send_custom_refresh(r, conf);
        }
    }

    return rc;
}

static ngx_int_t
ngx_http_bot_protection_got_variable(ngx_http_request_t *r,
                                     ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_bot_protection_ctx_t *ctx;
    ngx_http_bot_protection_conf_t *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection ngx_http_bot_protection_got_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_bot_protection_module);
    if (conf->enable == BOT_PROTECTION_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_protection_module);
    if (ctx == NULL) {
        ctx = ngx_http_bot_protection_get_uid(r, conf);
        if (ctx == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    if (ctx->uid_got == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_memcpy(v->data, ctx->uid_got, MD5_DIGEST_LENGTH * 2);
    v->len = MD5_DIGEST_LENGTH * 2;

    return NGX_OK;
}


#ifdef PROBE_COOKIE_ENCRYPTION

static ngx_int_t
ngx_http_bot_protection_enc_key_variable(ngx_http_request_t *r,
                                         ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_bot_protection_ctx_t *ctx;
    ngx_http_bot_protection_conf_t *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection ngx_http_bot_protection_enc_key_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_bot_protection_module);
    if (conf->enable == BOT_PROTECTION_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!conf->refresh_encrypt_cookie) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_protection_module);
    if (ctx == NULL || ctx->encrypt_key == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_hex_dump(v->data, ctx->encrypt_key, MD5_DIGEST_LENGTH);
    v->len = MD5_DIGEST_LENGTH * 2;

    return NGX_OK;
}

static ngx_int_t
ngx_http_bot_protection_enc_salt_variable(ngx_http_request_t *r,
                                          ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_bot_protection_ctx_t *ctx;
    ngx_http_bot_protection_conf_t *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection ngx_http_bot_protection_enc_salt_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_bot_protection_module);
    if (conf->enable == BOT_PROTECTION_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!conf->refresh_encrypt_cookie) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_protection_module);
    if (ctx == NULL || ctx->encrypt_key == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

//     todo salt should be change on the fly nor per reset
//     testcookie_refresh_encrypt_cookie_key  ?;
//     testcookie_refresh_encrypt_cookie_iv  ?;
//
    u_char salt_value[] = "0123456789";
    int count;
    for (count = 0; count < 10; count++) {
        salt_value[count] = ngx_random_number * count;
    }
    salt_value[9] = 0;

    ngx_hex_dump(v->data, salt_value, MD5_DIGEST_LENGTH);
    v->len = MD5_DIGEST_LENGTH * 2;

    return NGX_OK;
}

static ngx_int_t
ngx_http_bot_protection_enc_set_variable(ngx_http_request_t *r,
                                         ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_bot_protection_ctx_t *ctx;
    ngx_http_bot_protection_conf_t *conf;

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    EVP_CIPHER_CTX *evp_ctx;
#else
    EVP_CIPHER_CTX evp_ctx;
#endif

    u_char *c;
    int len;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection ngx_http_bot_protection_enc_set_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_bot_protection_module);
    if (conf->enable == BOT_PROTECTION_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!conf->refresh_encrypt_cookie) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH * 2);
    if (v->data == NULL) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_protection_module);
    if (ctx == NULL || ctx->encrypt_key == NULL || ctx->encrypt_iv == NULL || ctx->uid_set == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    c = (u_char *) ngx_palloc(r->pool, MD5_DIGEST_LENGTH);
    if (c == NULL) {
        v->not_found = 1;
        return NGX_ERROR;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(evp_ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);

    if (!EVP_CipherInit_ex(evp_ctx, NULL, NULL, ctx->encrypt_key, ctx->encrypt_iv, 1)) {
        v->not_found = 1;
        EVP_CIPHER_CTX_free(evp_ctx);
        return NGX_ERROR;
    }

    if (!EVP_CipherUpdate(evp_ctx, c, &len, ctx->uid_set, MD5_DIGEST_LENGTH)) {
        v->not_found = 1;
        EVP_CIPHER_CTX_free(evp_ctx);
        return NGX_ERROR;
    }

    EVP_CIPHER_CTX_free(evp_ctx);

#else
    EVP_CIPHER_CTX_init(&evp_ctx);
    if (!EVP_EncryptInit_ex(&evp_ctx, EVP_aes_128_cbc(), NULL, ctx->encrypt_key, ctx->encrypt_iv)) {
        v->not_found = 1;
        EVP_CIPHER_CTX_cleanup(&evp_ctx);
        return NGX_ERROR;
    }

    if (!EVP_EncryptUpdate(&evp_ctx, c, &len, ctx->uid_set, MD5_DIGEST_LENGTH)) {
        v->not_found = 1;
        EVP_CIPHER_CTX_cleanup(&evp_ctx);
        return NGX_ERROR;
    }
/*
    if (!EVP_EncryptFinal_ex(&evp_ctx, c, &len)) {
        v->not_found = 1;
        EVP_CIPHER_CTX_cleanup(&evp_ctx);
        return NGX_ERROR;
    }
*/
    EVP_CIPHER_CTX_cleanup(&evp_ctx);
#endif

    ngx_hex_dump(v->data, c, MD5_DIGEST_LENGTH);

    v->len = MD5_DIGEST_LENGTH * 2;

    return NGX_OK;
}

static ngx_int_t
ngx_http_bot_protection_enc_iv_variable(ngx_http_request_t *r,
                                        ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_bot_protection_ctx_t *ctx;
    ngx_http_bot_protection_conf_t *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ngx_http_bot_protection_enc_iv_variable");

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_bot_protection_module);
    if (conf->enable == BOT_PROTECTION_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!conf->refresh_encrypt_cookie) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_protection_module);
    if (ctx == NULL || ctx->encrypt_iv == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_hex_dump(v->data, ctx->encrypt_iv, MD5_DIGEST_LENGTH);
    v->len = MD5_DIGEST_LENGTH * 2;

    return NGX_OK;
}

#endif

static ngx_int_t
ngx_http_bot_protection_timestamp_variable(ngx_http_request_t *r,
                                           ngx_http_variable_value_t *v, uintptr_t data) {
    u_char *p;

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%P", ngx_time()) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_bot_protection_set_variable(ngx_http_request_t *r,
                                     ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_bot_protection_ctx_t *ctx;
    ngx_http_bot_protection_conf_t *conf;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ngx_http_bot_protection_set_variable");


    conf = ngx_http_get_module_loc_conf(r, ngx_http_bot_protection_module);
    if (conf->enable == BOT_PROTECTION_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_protection_module);
    if (ctx == NULL || ctx->uid_set == NULL) {
        ctx = ngx_http_bot_protection_get_uid(r, conf);
        if (ctx == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    v->data = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_hex_dump(v->data, ctx->uid_set, MD5_DIGEST_LENGTH);
    v->len = MD5_DIGEST_LENGTH * 2;

    return NGX_OK;
}

static ngx_int_t
ngx_http_bot_protection_ok_variable(ngx_http_request_t *r,
                                    ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_bot_protection_ctx_t *ctx;
    ngx_http_bot_protection_conf_t *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ngx_http_bot_protection_ok_variable");

    conf = ngx_http_get_module_loc_conf(r, ngx_http_bot_protection_module);
    if (conf->enable == BOT_PROTECTION_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_protection_module);
    if (ctx == NULL) {
        ctx = ngx_http_bot_protection_get_uid(r, conf);
        if (ctx == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    v->len = 1;
    v->data = (u_char *) ngx_pcalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx->ok == 1) {
        ngx_memcpy(v->data, "1", sizeof("1") - 1);
    } else {
        ngx_memcpy(v->data, "0", sizeof("0") - 1);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_bot_protection_nexturl_variable(ngx_http_request_t *r,
                                         ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_bot_protection_conf_t *conf;
    u_char *p, *location;
    size_t len;
    uintptr_t escape;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection ngx_http_bot_protection_nexturl_variable");

    if (r->headers_out.location == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = r->headers_out.location->value.len;
    location = r->headers_out.location->value.data;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_bot_protection_module);
    if (conf->enable == BOT_PROTECTION_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    escape = 2 * ngx_escape_uri(NULL, location, len, NGX_ESCAPE_REFRESH);

    v->len = len + escape;

    v->data = (u_char *) ngx_pcalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    p = v->data;

    if (escape == 0) {
        p = ngx_cpymem(p, location, len);
    } else {
        p = (u_char *) ngx_escape_uri(p, location, len, NGX_ESCAPE_REFRESH);
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}



struct attack *find(ngx_http_request_t *r, char key[]) {
    struct attack *current = head;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "bot_protection hashmap looking for %s",
                  key);
    if (head == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "bot_protection hashmap return head==NULL");
        return NULL;
    }
    while (ngx_strcmp(current->token, key) != 0) {
        if (current->next == NULL) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "bot_protection hashmap return NULL");
            return NULL;
        } else {
            current = current->next;
        }
    }
    return current;
}

void attack_verbose(ngx_http_request_t *r) {
    struct attack *ptr = head;
    int i = 0;
    while (ptr != NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "bot_protection suspected verbose: [%d] client [%s]  request forgery [%d]",
                      ++i, head->token, head->count);
        ptr = ptr->next;
    }
}

int get_suspected_len() {
    int length = 0;
    struct attack *current;

    for (current = head; current != NULL; current = current->next) {
        length++;
    }
    return length;
}

int  *pop_attack(ngx_http_request_t *r, char *key) {
    struct attack *current = head;
    struct attack *previous = NULL;
    if (head == NULL) {
        return NULL;
    }

    while (ngx_strcmp(current->token, key) != 0) {
        if (current->next == NULL) {
            return NULL;
        } else {
            previous = current;
            current = current->next;
        }
    }
    if (current == head) {
        head = head->next;
    } else {
        previous->next = current->next;
    }
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "bot_protection  token %s revoked from suspected list successfully.", key);
    return (int *) 1;
}

int push_attack(ngx_http_request_t *r, char key[], int count) {
    struct attack *new_attack = (struct attack *) malloc(sizeof(struct attack));
    if (new_attack == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "bot_protection  error memory allocation.");
        return 1;
    }
    strncpy(new_attack->token, key, 512);
    new_attack->count = count;
    new_attack->next = head;
    head = new_attack;
    return 0;
}

int decrypt_token(ngx_http_request_t *r, unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                  unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;

    int plaintext_len;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "bot_protection decrypt_token params ciphertext len->(%d), aes.key[%s]-> len(%d), aes.iv[%s]-> len(%d)",
                  ciphertext_len, key, strlen((const char *) key), iv, strlen((const char *) iv));

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection error init evp context");
    }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bot_protection error init cvp and context decryption");
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection error init evp decrypt update");
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection error init evp decrypt finalize");
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


static ngx_http_bot_protection_ctx_t *
ngx_http_bot_protection_get_uid(ngx_http_request_t *r, ngx_http_bot_protection_conf_t *conf) {
    ngx_int_t n;
#define TOKEN_SIZE 253

    char token[TOKEN_SIZE + 1];
    memset(token, '\0', TOKEN_SIZE + 1);

    char key[33];
    memset(key, '\0', 32 + 1);

    unsigned char decrypted_str[1024];
    int decrypted_str_len;

    unsigned char cipher_str[97];
    char aes_key_str[33];
    char aes_iv_str[17];
    char time_stamp[14];
    int i, j;


    ngx_table_elt_t **cookies;
    ngx_http_bot_protection_conf_t *ucf = conf;
    ngx_http_bot_protection_ctx_t *ctx;
    struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
    u_char *p;
    in_addr_t addr;
    struct sockaddr_in6 *sin6;
#endif
    ngx_md5_t md5;
    ngx_str_t value;
    ngx_str_t *check;
    ngx_http_variable_value_t *vv = NULL;
    u_char complex_hash[MD5_DIGEST_LENGTH];
    u_char complex_hash_hex[MD5_DIGEST_LENGTH * 2];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection version %s", MODULE_VERSION);

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_protection_module);
    if (ctx == NULL) {
        ctx = (ngx_http_bot_protection_ctx_t *) ngx_pcalloc(r->pool, sizeof(ngx_http_bot_protection_ctx_t));
        if (ctx == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bot_protection return NULL cause of ctx == NULL");
            return NULL;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_bot_protection_module);
    }

#ifdef PROBE_COOKIE_ENCRYPTION
    if (conf->refresh_encrypt_cookie == 1) {
        if (conf->refresh_encrypt_cookie_key == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "bot_protection Encryption key is not defined, skipping to prevent errors");
            return NULL;
        }
        ctx->encrypt_key = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH);
        if (ctx->encrypt_key == NULL) {
            return NULL;
        }
        ctx->encrypt_iv = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH);
        if (ctx->encrypt_iv == NULL) {
            return NULL;
        }
        ngx_memcpy(ctx->encrypt_key, conf->refresh_encrypt_cookie_key, MD5_DIGEST_LENGTH);
        if (conf->refresh_encrypt_cookie_iv == NULL) {
            /*
                SHA1/SHA2 eats too much CPU
                do we _really_ need cryptographically strong random here in our case ?
            */
            if (RAND_bytes(ctx->encrypt_iv, MD5_DIGEST_LENGTH) != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "bot_protection Openssl random IV generation error");
                return NULL;
            }
        } else {
            ngx_memcpy(ctx->encrypt_iv, conf->refresh_encrypt_cookie_iv, MD5_DIGEST_LENGTH);
        }
    }
#endif

    switch (r->connection->sockaddr->sa_family) {
        case AF_INET:

            /* AF_INET only */
            sin = (struct sockaddr_in *) r->connection->sockaddr;

            if (conf->whitelist != NULL) {
                vv = (ngx_http_variable_value_t *) ngx_radix32tree_find(conf->whitelist, ntohl(sin->sin_addr.s_addr));
            }
            break;

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
            p = sin6->sin6_addr.s6_addr;

            if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
                addr = p[12] << 24;
                addr += p[13] << 16;
                addr += p[14] << 8;
                addr += p[15];
                if (conf->whitelist != NULL) {
                    vv = (ngx_http_variable_value_t *) ngx_radix32tree_find(conf->whitelist, ntohl(addr));
                }
            } else {
                if (conf->whitelist6 != NULL) {
                    vv = (ngx_http_variable_value_t *) ngx_radix128tree_find(conf->whitelist6, p);
                }
            }
            break;

#endif
    }

    if (vv != NULL && vv->len > 0) {
        ctx->ok = 1;
        return ctx;
    }

    ctx->ok = 0;

    if (ucf->session_key.value.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "bot_protection Session key is not defined, skipping to prevent leaks");
        return NULL;
    }

    if (ngx_http_complex_value(r, &ucf->session_key, &value) != NGX_OK) {
        return ctx;
    }

    check = &value;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, check->data, check->len);
    if (conf->secret.len > 0) {
        ngx_md5_update(&md5, conf->secret.data, conf->secret.len);
    }
    ngx_md5_final(complex_hash, &md5);

    ctx->uid_set = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH);
    if (ctx->uid_set == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bot_protection return NULL cause of ctx->uid_set == NULL");
        return NULL;
    }

    ngx_memcpy(ctx->uid_set, complex_hash, MD5_DIGEST_LENGTH);
    ngx_hex_dump(complex_hash_hex, complex_hash, MD5_DIGEST_LENGTH);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection ngx_hex_dump(complex_hash_hex: %s", complex_hash_hex);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection input data: \"%V\"", check);


    n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->name,
                                          &ctx->cookie);

    if (n == NGX_DECLINED) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection return ctx cause of NGX_DECLINED");
        return ctx;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection ctx uid cookie: \"%V\"", &ctx->cookie);
    cookies = r->headers_in.cookies.elts;
    if (ngx_strcmp(&cookies[n]->value, DEFAULT_COOKIE_NAME)) { // yup, ironfox cookie found

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bot_protection client sent cookies \"%V\"",
                       &cookies[n]->value);


    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                       r->connection->log,
                       0,
                       "bot_protection %s cookie not found.",
                       DEFAULT_COOKIE_NAME
        );

    }


#if (NGX_DEBUG)


#endif

    if (ctx->cookie.len != MD5_DIGEST_LENGTH * 2) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bot_protection ctx->cookie.len(%d) != MD5_DIGEST_LENGTH * 2",
                       ctx->cookie.len);
        return ctx;
    }

    if (!ngx_ishex(ctx->cookie.data, ctx->cookie.len)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "bot_protection !ngx_ishex(ctx->cookie.data, ctx->cookie.len)");
        return ctx;
    }

    ctx->uid_got = (u_char *) ngx_pcalloc(r->pool, MD5_DIGEST_LENGTH * 2);
    if (ctx->uid_got == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ctx->uid_got == NULL");
        return ctx;
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ctx->cookie.data %s  len: %d",
                   ctx->cookie.data, ctx->cookie.len);
    ngx_memcpy(ctx->uid_got, ctx->cookie.data, ctx->cookie.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ctx->uid_got [%s]",
                   ctx->uid_got);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection complex_hash_hex [%s]",
                   complex_hash_hex);
    if (ngx_memcmp(ctx->uid_got, complex_hash_hex, MD5_DIGEST_LENGTH * 2) == 0) {
        // ironfox cookie hash matched, start fingerprinting
        if (conf->anomaly_detection == ANOMALY_DETECTION_OFF) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ignore anomaly detection...");
            ctx->ok = 1;
            return ctx;
        }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection start anomaly detection...");

        int cookie_len = 1024;//todo 512 engouh
        char cookie_container[cookie_len];
        memset(cookie_container, 0, cookie_len);
        ngx_snprintf((unsigned char *)cookie_container, cookie_len, "%V", &cookies[n]->value);
        cookie_container[cookie_len + 1] = '\0';
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection cookie container value -> %s",
                       cookie_container);

        if (strstr(cookie_container, TOKEN_NAME) != NULL && strstr(cookie_container, KEY_NAME) != NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "bot_protection token and key exists in cookie container");
            // extract encrypted token
            char *token_ptr = strstr(cookie_container, TOKEN_NAME);
            int token_index = token_ptr - cookie_container;
            j = 0;
            for (i = token_index + TOKEN_NAME_LENGTH; i < token_index + TOKEN_NAME_LENGTH + TOKEN_SIZE; ++i) {
                sprintf(&token[j], "%c", cookie_container[i]);
                j++;
            }

            token[j] = '\0';
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection token.value %s",
                           token);

            // extract key
            char *key_ptr = strstr(cookie_container, KEY_NAME);
            int key_index = key_ptr - cookie_container;
            int l = 0;
            for (i = key_index + KEY_NAME_LENGTH; i < key_index + KEY_NAME_LENGTH + 32; ++i) {
                sprintf(&key[l], "%c", cookie_container[i]);
                l++;
            }
            key[l] = '\0';
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection (key in cookie) key.value %s",
                           key);

            // de-obfuscation's and decrypt token and extract main value



            if (strlen(token) > 0) {

                memset(cipher_str, 0, 97);
                memset(aes_key_str, 0, 33);
                memset(aes_iv_str, 0, 17);
                memset(time_stamp, 0, 14);
                // AES key
                j = 0;
                for (i = 0; i < 32; ++i) {
                    sprintf(&aes_key_str[j], "%c", token[i]);
                    j++;
                }
                aes_key_str[32] = '\0';
                // AES iv
                j = 0;
                for (int k = 32; k < 48; ++k) {
                    sprintf(&aes_iv_str[j], "%c", token[k]);
                    j++;
                }
                aes_iv_str[16] = '\0';


                unsigned char ukey[33];
                unsigned char uiv[17];
                memset(ukey, 0, 32);
                memset(uiv, 0, 16);


                for (i = 0; i < 32; i++) {
                    sscanf(aes_key_str + i, "%c", &ukey[i]);
                }
                ukey[32] = '\0';
                for (i = 0; i < 16; i++) {
                    sscanf(aes_iv_str + i, "%c", &uiv[i]);
                }
                uiv[16] = '\0';

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "bot_protection key [%s] ukey[%s]-> len(%d)",
                              aes_key_str, ukey, strlen((const char *) ukey));

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "bot_protection iv [%s] uiv[%s]->len(%d)",
                              aes_iv_str, uiv, strlen((const char *) uiv));

                char payload[114], *pos = payload;
                //memset(payload,0,strlen(payload));
                j = 0;
                for (int k = 48; k < 144; ++k) {
                    sprintf(&payload[j], "%c", token[k]);
                    j++;
                }
                //payload[114] = '\0';


                j = 0;
                for (size_t c = 0; c < sizeof cipher_str / sizeof *cipher_str; c++) {
                    sscanf(pos, "%2hhX", &cipher_str[c]);
                    pos += 2;
                }
                cipher_str[48] = '\0';
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "bot_protection cipher_str  payload len %d",
                              j);


                // extract timestamp
                j = 0;
                memset(time_stamp, 0, 14);
                for (int k = 144; k < 154; ++k) {
                    sprintf(&time_stamp[j], "%c", token[k]);
                    j++;
                }

                //get request ts
                time_t rawtime;
                rawtime = strtol(time_stamp, NULL, 0);
                //ctime(&rawtime);
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "bot_protection extract request raw timestamp =>  %l", rawtime);
                struct tm *req_ts = localtime(&rawtime);
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "bot_protection extract request timestamp =>  %02d:%02d:%02d", req_ts->tm_hour,
                              req_ts->tm_min, req_ts->tm_sec);
                int req_ts_sec = req_ts->tm_sec;
                int req_ts_min = (req_ts->tm_min) * 60;
                int req_ts_hr = (req_ts->tm_hour) * 3600;


                int total_req_sec = req_ts_hr + req_ts_min + req_ts_sec;

                //get server ts
                struct timeval tv;
                struct tm *server_ts;
                gettimeofday(&tv, NULL);

                server_ts = localtime((const time_t *) &tv);
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "bot_protection get server timestamp =>  %02d:%02d:%02d", server_ts->tm_hour,
                              server_ts->tm_min, server_ts->tm_sec);
                int total_server_sec = (server_ts->tm_hour) * (3600) + (server_ts->tm_min) * (60) + server_ts->tm_sec;

                // first check the token ttl for replay attack (CSRF) then decrypt token, reduce decryption overhead ;-)
                int ts_diff = total_server_sec - total_req_sec;
                //todo TOKEN_TTL_THRESHOLD_SECOND & CSRF_BLOCKING_THRESHOLD configurable
                if (ts_diff > TOKEN_TTL_THRESHOLD_SECOND || ts_diff < 0) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                  "bot_protection Ooooppsss! token ttl (%d) threshold or negative, maybe CSRF attack!",
                                  ts_diff);

                    if (find(r, key) == NULL) {
                        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                      "bot_protection add token to canary, check for false positive!");
                        push_attack(r, key, 1);
                    } else {
                        struct attack *node = find(r, key);
                        if (node->count > CSRF_BLOCKING_THRESHOLD) {
                            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                          "bot_protection canary triggered. reply token %s for %d times, reject request",
                                          node->token,
                                          node->count++);
                            //todo add this fingerprint to black list  or forward to captcha!
                            return NULL;
                        }
                        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                      "bot_protection CSRF triggered token %s for %d times", node->token,
                                      node->count++);
                        struct attack *temp = find(r, key);
                        pop_attack(r, key);
                        push_attack(r, temp->token, temp->count++);

                    }
                } else {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection token ttl (%d) valid",
                                  ts_diff);
                    pop_attack(r, key);
                }
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "bot_protection total suspected clients => %d ",
                              get_suspected_len());
                attack_verbose(r);

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "bot_protection before decryption => key:[%s] iv:[%s] timestamp:[%s] ",
                              ukey, uiv, time_stamp);

                decrypted_str_len = decrypt_token(r, cipher_str,
                                                  strlen((const char *) cipher_str),
                                                  (unsigned char *) ukey,
                                                  (unsigned char *) uiv,
                                                  decrypted_str);

                decrypted_str[decrypted_str_len] = '\0';
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection  AES decrypted result: %s",
                              decrypted_str);



                /////////////////////////////////////////////////////////////////////

                if (ngx_strcmp(key, decrypted_str) == 0) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection token and key matched ");


                    ctx->ok = 1;
                    return ctx;
                } else {
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "bot_protection not matched! token.value %s and key.value %s", decrypted_str, key);
                }

            } else {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection  error parsing token, len(%d)",
                              strlen(token));
            }
        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection token or key not found");
        }

        // ctx->ok = 1;
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bot_protection ctx->ok != 1 ");
    }

    return ctx;
}


static ngx_int_t
ngx_http_bot_protection_set_uid(ngx_http_request_t *r, ngx_http_bot_protection_ctx_t *ctx,
                                ngx_http_bot_protection_conf_t *conf) {
#define BOT_PROTECTION_COOKIE_SECURE_FLAG_ON  1
#define BOT_PROTECTION_COOKIE_SECURE_FLAG_OFF 0

    u_char *cookie, *p;
    size_t len;
    ngx_table_elt_t *set_cookie, *p3p;
    ngx_uint_t secure_flag_set = BOT_PROTECTION_COOKIE_SECURE_FLAG_OFF;
    ngx_str_t secure_flag;

    if (conf->redirect_via_refresh && conf->refresh_template.len > 0) {
        return NGX_OK;
    }

    len = conf->name.len + MD5_DIGEST_LENGTH * 2 + 2;

    if (conf->path.len) {
        len += conf->path.len;
    }

    if (conf->expires) {
        len += sizeof(expires) - 1;
    }

    if (conf->domain.len) {
        len += conf->domain.len;
    }

    if (conf->httponly_flag) {
        len += sizeof("; HttpOnly") - 1;
    }

    if (conf->secure_flag != NULL
        && ngx_http_complex_value(r, conf->secure_flag, &secure_flag) == NGX_OK
        && secure_flag.len
        && (secure_flag.len != 3 || secure_flag.data[2] != 'f' || secure_flag.data[1] != 'f' ||
            secure_flag.data[0] != 'o')) {
        secure_flag_set = BOT_PROTECTION_COOKIE_SECURE_FLAG_ON;
        len += sizeof("; Secure") - 1;
    }

    cookie = ngx_palloc(r->pool, len);
    if (cookie == NULL || ctx->uid_set == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(cookie, "%V=", &conf->name);
    p = ngx_hex_dump(p, ctx->uid_set, MD5_DIGEST_LENGTH);

    if (conf->expires == NGX_HTTP_BOT_PROTECTION_TTL_MAX_EXPIRES) {
        p = ngx_cpymem(p, expires, sizeof(expires) - 1);
    } else if (conf->expires) {
        p = ngx_cpymem(p, expires, sizeof("; expires=") - 1);
        p = ngx_http_cookie_time(p, ngx_time() + conf->expires);
    }

    p = ngx_copy(p, conf->path.data, conf->path.len);
    p = ngx_copy(p, conf->domain.data, conf->domain.len);

    if (conf->httponly_flag) {
        p = ngx_cpymem(p, (u_char *) "; HttpOnly", sizeof("; HttpOnly") - 1);
    }

    if (secure_flag_set == BOT_PROTECTION_COOKIE_SECURE_FLAG_ON) {
        p = ngx_cpymem(p, (u_char *) "; Secure", sizeof("; Secure") - 1);
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    set_cookie->key.len = sizeof("Set-Cookie") - 1;
    set_cookie->key.data = (u_char *) "Set-Cookie";
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "bot_protection testcookie cookie uid: \"%V\"", &set_cookie->value);

    if (conf->p3p.len == 0) {
        return NGX_OK;
    }

    p3p = ngx_list_push(&r->headers_out.headers);
    if (p3p == NULL) {
        return NGX_ERROR;
    }

    p3p->hash = 1;
    p3p->key.len = sizeof("P3P") - 1;
    p3p->key.data = (u_char *) "P3P";
    p3p->value = conf->p3p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_bot_protection_add_variables(ngx_conf_t *cf) {
    ngx_http_variable_t *var;


    var = ngx_http_add_variable(cf, &ngx_http_bot_protection_got, NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_got_variable;

    var = ngx_http_add_variable(cf, &ngx_http_bot_protection_set, NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_set_variable;

    var = ngx_http_add_variable(cf, &ngx_http_bot_protection_ok, NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_ok_variable;

    var = ngx_http_add_variable(cf, &ngx_http_bot_protection_nexturl, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_nexturl_variable;

    var = ngx_http_add_variable(cf, &ngx_http_bot_protection_timestamp, NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_timestamp_variable;

#ifdef PROBE_COOKIE_ENCRYPTION
    var = ngx_http_add_variable(cf, &ngx_http_bot_protection_enc_key, NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_enc_key_variable;


    var = ngx_http_add_variable(cf,
                                &ngx_http_bot_protection_enc_iv,
                                NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_enc_iv_variable;

    var = ngx_http_add_variable(cf, &ngx_http_bot_protection_enc_set, NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_enc_set_variable;


    var = ngx_http_add_variable(cf,
                                &ngx_http_bot_protection_enc_salt,
                                NGX_HTTP_VAR_NOHASH | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_bot_protection_enc_salt_variable;


#endif

    return NGX_OK;
}





static void *
ngx_http_bot_protection_create_conf(ngx_conf_t *cf) {
    ngx_http_bot_protection_conf_t *conf;

    conf = (ngx_http_bot_protection_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_bot_protection_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->name.len = 0;
     *     conf->name.data = NULL;
     *     conf->domain.len = 0;
     *     conf->domain.data = NULL;
     *     conf->path.len = 0;
     *     conf->path.data = NULL;
     *     conf->p3p.len = 0;
     *     conf->p3p.data = NULL;
     *     conf->arg.len = 0;
     *     conf->arg.data = NULL;
     *     conf->secret.len = 0;
     *     conf->secret.data = NULL;
     *     conf->session_key.value.data = NULL;
     *     conf->session_key.value.len = 0;
     *     conf->fallback.len = 0;
     *     conf->fallback.data = NULL;
     *     conf->refresh_template.len = 0;
     *     conf->refresh_template.data = NULL;
     *     conf->secure_flag = NULL;
     *     conf->pass_var = NULL;
     */


    conf->enable = NGX_CONF_UNSET;
    conf->anomaly_detection = NGX_CONF_UNSET;
    conf->expires = NGX_CONF_UNSET;
    conf->max_attempts = NGX_CONF_UNSET;
    conf->whitelist = NULL;
#if (NGX_HAVE_INET6)
    conf->whitelist6 = NULL;
#endif
    conf->fallback_lengths = NULL;
    conf->fallback_values = NULL;
    conf->redirect_to_https = NGX_CONF_UNSET;
    conf->get_only = NGX_CONF_UNSET;
    conf->deny_keepalive = NGX_CONF_UNSET;
    conf->redirect_via_refresh = NGX_CONF_UNSET;
    conf->refresh_template_lengths = NULL;
    conf->refresh_template_values = NULL;
    conf->refresh_status = NGX_CONF_UNSET_UINT;
    conf->internal = NGX_CONF_UNSET;
    conf->httponly_flag = NGX_CONF_UNSET;
    conf->secure_flag = NULL;
    conf->pass_var = NULL;
    conf->port_in_redirect = NGX_CONF_UNSET;

#ifdef PROBE_COOKIE_ENCRYPTION
    conf->refresh_encrypt_cookie = NGX_CONF_UNSET;
    conf->refresh_encrypt_cookie_key = NULL;
    conf->refresh_encrypt_cookie_iv = NULL;
#endif

    return conf;
}


static char *
ngx_http_bot_protection_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_bot_protection_conf_t *prev = parent;
    ngx_http_bot_protection_conf_t *conf = child;
    ngx_uint_t n;
    ngx_http_script_compile_t sc;

    ngx_conf_merge_uint_value(conf->enable, prev->enable, BOT_PROTECTION_OFF);
    ngx_conf_merge_uint_value(conf->anomaly_detection, prev->anomaly_detection, ANOMALY_DETECTION_ON);

    ngx_conf_merge_str_value(conf->name, prev->name, DEFAULT_COOKIE_NAME);
    ngx_conf_merge_str_value(conf->domain, prev->domain, "");
    ngx_conf_merge_str_value(conf->path, prev->path, "; path=/");
    ngx_conf_merge_str_value(conf->p3p, prev->p3p, "");
    ngx_conf_merge_str_value(conf->arg, prev->arg, "");
    ngx_conf_merge_str_value(conf->secret, prev->secret, "");

    ngx_conf_merge_str_value(conf->fallback, prev->fallback, "");
    ngx_conf_merge_str_value(conf->refresh_template, prev->refresh_template, "");
    ngx_conf_merge_uint_value(conf->refresh_status, prev->refresh_status, NGX_HTTP_OK);

    ngx_conf_merge_value(conf->max_attempts, prev->max_attempts, RFC1945_ATTEMPTS);
    ngx_conf_merge_sec_value(conf->expires, prev->expires, 0);

    if (conf->whitelist == NULL) {
        conf->whitelist = prev->whitelist;
    }

#if (NGX_HAVE_INET6)
    if (conf->whitelist6 == NULL) {
        conf->whitelist6 = prev->whitelist6;
    }
#endif

    if (conf->session_key.value.data == NULL) {
        conf->session_key = prev->session_key;
    }

    ngx_conf_merge_value(conf->redirect_to_https, prev->redirect_to_https, 0);
    ngx_conf_merge_value(conf->get_only, prev->get_only, 0);
    ngx_conf_merge_value(conf->deny_keepalive, prev->deny_keepalive, 0);
    ngx_conf_merge_value(conf->redirect_via_refresh, prev->redirect_via_refresh, 0);
    ngx_conf_merge_value(conf->internal, prev->internal, 0);
    ngx_conf_merge_value(conf->httponly_flag, prev->httponly_flag, 0);
    ngx_conf_merge_value(conf->port_in_redirect, prev->port_in_redirect, 0);

#ifdef PROBE_COOKIE_ENCRYPTION
    ngx_conf_merge_value(conf->refresh_encrypt_cookie, prev->refresh_encrypt_cookie, NGX_CONF_UNSET);
    if (conf->refresh_encrypt_cookie_key == NULL) {
        conf->refresh_encrypt_cookie_key = prev->refresh_encrypt_cookie_key;
    }
    if (conf->refresh_encrypt_cookie_iv == NULL) {
        conf->refresh_encrypt_cookie_iv = prev->refresh_encrypt_cookie_iv;
    }
#endif

    /* initializing variables for fallback url */
    n = ngx_http_script_variables_count(&conf->fallback);
    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &conf->fallback;
        sc.lengths = &conf->fallback_lengths;
        sc.values = &conf->fallback_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /* initializing variables for refresh template */
    n = ngx_http_script_variables_count(&conf->refresh_template);
    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &conf->refresh_template;
        sc.lengths = &conf->refresh_template_lengths;
        sc.values = &conf->refresh_template_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->secure_flag == NULL) {
        conf->secure_flag = prev->secure_flag;
    }

    if (conf->pass_var == NULL) {
        conf->pass_var = prev->pass_var;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_bot_protection_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (NULL == h) {
        return NGX_ERROR;
    }
    *h = ngx_http_bot_protection_handler;

    return NGX_OK;
}


static char *
ngx_http_bot_protection_domain(ngx_conf_t *cf, void *post, void *data) {
    ngx_str_t *domain = data;

    u_char *p, *new;

    if (ngx_strcmp(domain->data, "none") == 0) {
        domain->len = 0;
        domain->data = (u_char *) "";

        return NGX_CONF_OK;
    }

    new = ngx_palloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; domain=", sizeof("; domain=") - 1);
    ngx_memcpy(p, domain->data, domain->len);

    domain->len += sizeof("; domain=") - 1;
    domain->data = new;

    return NGX_CONF_OK;
}


static char *
ngx_http_bot_protection_path(ngx_conf_t *cf, void *post, void *data) {
    ngx_str_t *path = data;

    u_char *p, *new;

    new = ngx_palloc(cf->pool, sizeof("; path=") - 1 + path->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; path=", sizeof("; path=") - 1);
    ngx_memcpy(p, path->data, path->len);

    path->len += sizeof("; path=") - 1;
    path->data = new;

    return NGX_CONF_OK;
}


static char *
ngx_http_bot_protection_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_bot_protection_conf_t *ucf = conf;

    ngx_str_t *value;

    if (ucf->expires != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "max") == 0) {
        ucf->expires = NGX_HTTP_BOT_PROTECTION_TTL_MAX_EXPIRES;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ucf->expires = 0;
        return NGX_CONF_OK;
    }

    ucf->expires = ngx_parse_time(&value[1], 1);
    if (ucf->expires == NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_bot_protection_p3p(ngx_conf_t *cf, void *post, void *data) {
    ngx_str_t *p3p = data;

    if (ngx_strcmp(p3p->data, "none") == 0) {
        p3p->len = 0;
        p3p->data = (u_char *) "";
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_bot_protection_fallback_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_script_compile_t sc;
    ngx_str_t *value;
    ngx_uint_t n;
    ngx_http_bot_protection_conf_t *ucf = conf;

    if (ucf->fallback.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0 || ngx_strcmp(value[1].data, "none") == 0) {
        ucf->fallback.len = 0;
        ucf->fallback.data = (u_char *) "";
        return NGX_CONF_OK;
    }

    ucf->fallback = value[1];

    n = ngx_http_script_variables_count(&ucf->fallback);

    if (n == 0) {
        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &ucf->fallback;
    sc.lengths = &ucf->fallback_lengths;
    sc.values = &ucf->fallback_values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_bot_protection_session_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value;
    ngx_http_compile_complex_value_t ccv;
    ngx_http_bot_protection_conf_t *ucf = conf;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    if (value[1].len == 0) {
        return NGX_CONF_ERROR;
    }

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ucf->session_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_bot_protection_refresh_template_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_script_compile_t sc;
    ngx_str_t *value;
    ngx_uint_t n;
    ngx_http_bot_protection_conf_t *ucf = conf;
    if (ucf->refresh_template.data) {
        return "is duplicate";
    }

    value = cf->args->elts;
    // if user parches then he/she can use custom template
    if (value[1].len == 0 || ngx_strcmp(value[1].data, "ironfox") == 0) {
        ucf->refresh_template.len = JS_ENGIE_LEN;
        ucf->refresh_template.data = (u_char *) JS_ENGIE_BODY;
        return NGX_CONF_OK;
    }


    // add by khalegh, custome js tempalate
    if (value[1].len == 0 || ngx_strcmp(value[1].data, "none") == 0) {
        ucf->refresh_template.len = 0;
        ucf->refresh_template.data = (u_char *) "";
        return NGX_CONF_OK;
    }
    if (value[1].len == 0 || ngx_strcmp(value[1].data, "basic") == 0) {
        ucf->refresh_template.len = 0;
        ucf->refresh_template.data = (u_char *) "";
        return NGX_CONF_OK;
    }
    if (value[1].len == 0 || ngx_strcmp(value[1].data, "medium") == 0) {
        ucf->refresh_template.len = JS_MEDIUM_LEN;
        ucf->refresh_template.data = (u_char *) JS_MEDIUM_BODY;
        return NGX_CONF_OK;
    }
    if (value[1].len == 0 || ngx_strcmp(value[1].data, "hard") == 0) {
        ucf->refresh_template.len = JS_HARD_LEN;
        ucf->refresh_template.data = (u_char *) JS_HARD_BODY;
        return NGX_CONF_OK;
    }
    ucf->refresh_template = value[1];

    n = ngx_http_script_variables_count(&ucf->refresh_template);
    if (n == 0) {
        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &ucf->refresh_template;
    sc.lengths = &ucf->refresh_template_lengths;
    sc.values = &ucf->refresh_template_values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_bot_protection_secret(ngx_conf_t *cf, void *post, void *data) {
    ngx_str_t *secret = data;


/*
    if (ngx_strcmp(secret->data, "none") == 0) {
        secret->len = 0;
        secret->data = (u_char *) "";
    }
*/

#ifdef PROBE_COOKIE_ENCRYPTION
    if (ngx_strcmp(secret->data, "random") == 0) {
        secret->len = MD5_DIGEST_LENGTH;
        if (RAND_bytes(secret->data, MD5_DIGEST_LENGTH) != 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bot_protection Openssl random secret generation error\n");
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }
#endif

    if (secret->len < MD5_DIGEST_LENGTH * 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection Secret value is too short, should be 32 bytes or more\n");
        return NGX_CONF_ERROR;
    }


    return NGX_CONF_OK;
}

static char *
ngx_http_bot_protection_max_attempts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_bot_protection_conf_t *ucf = conf;

    ngx_int_t n;
    ngx_str_t *value;

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);
    if (n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection invalid max number of attempts \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    /* RFC 1945 for HTTP/1.0 allows up to 5 hops */
    if (n > RFC1945_ATTEMPTS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection max attempts should must be less than 5");
        return NGX_CONF_ERROR;
    }

    ucf->max_attempts = n;

    return NGX_CONF_OK;
}

#ifdef PROBE_COOKIE_ENCRYPTION

static char *
ngx_http_bot_protection_set_encryption_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_bot_protection_conf_t *ucf = conf;
    ngx_str_t *value;

    value = cf->args->elts;

    ucf->refresh_encrypt_cookie_key = ngx_palloc(cf->pool, MD5_DIGEST_LENGTH);

    if (ngx_strcmp(value[1].data, "random") == 0) {
        if (RAND_bytes(ucf->refresh_encrypt_cookie_key, MD5_DIGEST_LENGTH) != 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bot_protection Openssl random key generation error \"%V\"", &value[0]);
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    if (value[1].len != MD5_DIGEST_LENGTH * 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection invalid parameter len, \"%V\" 16 hex bytes required", &value[0]);
        return NGX_CONF_ERROR;
    }

    if (ngx_hextobin(ucf->refresh_encrypt_cookie_key, value[1].data, value[1].len) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection invalid parameter len, \"%V\" 16 hex bytes required", &value[0]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_bot_protection_set_encryption_iv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_bot_protection_conf_t *ucf = conf;
    ngx_str_t *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "random") == 0) {
        ucf->refresh_encrypt_cookie_iv = NULL;
        return NGX_CONF_OK;
    }


    ucf->refresh_encrypt_cookie_iv = ngx_palloc(cf->pool, MD5_DIGEST_LENGTH);
    if (ucf->refresh_encrypt_cookie_iv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection IV memory allocation error");
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(value[1].data, "random2") == 0) {
        if (RAND_bytes(ucf->refresh_encrypt_cookie_iv, MD5_DIGEST_LENGTH) != 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bot_protection Openssl random IV generation error");
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    if (value[1].len != MD5_DIGEST_LENGTH * 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection invalid parameter len, \"%V\" 16 hex bytes required", &value[0]);
        return NGX_CONF_ERROR;
    }

    if (ngx_hextobin(ucf->refresh_encrypt_cookie_iv, value[1].data, value[1].len) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection invalid parameter len, \"%V\" 16 hex bytes required", &value[0]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#endif


static char *
ngx_http_bot_protection_whitelist_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *rv;
    ngx_conf_t save;
    ngx_http_bot_protection_conf_t *ucf = conf;
#if (NGX_HAVE_INET6)
    static struct in6_addr zero;
#endif

    ucf->whitelist = ngx_radix_tree_create(cf->pool, -1);
    if (ucf->whitelist == NULL) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_INET6)
    ucf->whitelist6 = ngx_radix_tree_create(cf->pool, -1);
    if (ucf->whitelist6 == NULL) {
        return NGX_CONF_ERROR;
    }
#endif

    if (ngx_radix32tree_find(ucf->whitelist, 0) != NGX_RADIX_NO_VALUE) {
        return NGX_CONF_ERROR;
    }

    if (ngx_radix32tree_insert(ucf->whitelist, 0, 0,
                               (uintptr_t) &ngx_http_variable_null_value) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_INET6)
    if (ngx_radix128tree_insert(ucf->whitelist6, zero.s6_addr, zero.s6_addr,
                                (uintptr_t) &ngx_http_variable_null_value) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }
#endif

    save = *cf;
    cf->handler = ngx_http_bot_protection_whitelist;
    cf->handler_conf = (char *) ucf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
ngx_http_bot_protection_whitelist(ngx_conf_t *cf, ngx_command_t *dummy, void *conf) {
    ngx_http_variable_value_t *old;
    ngx_int_t rc;
    ngx_str_t *value, file;
    ngx_uint_t i;
    ngx_cidr_t cidr;
    ngx_http_bot_protection_conf_t *ucf = conf;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "include") == 0) {
        file = value[1];

        if (ngx_conf_full_name(cf->cycle, &file, 1) == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        return ngx_conf_parse(cf, &file);
    }

    rc = ngx_ptocidr(&value[0], &cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection invalid parameter \"%V\"", &value[0]);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "bot_protection low address bits of %V are meaningless",
                           &value[0]);
    }

    switch (cidr.family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            /* fall through */

            for (i = 2; i; i--) {
                rc = ngx_radix128tree_insert(ucf->whitelist6, cidr.u.in6.addr.s6_addr,
                                             cidr.u.in6.mask.s6_addr,
                                             (uintptr_t) &ngx_http_variable_true_value);

                if (rc == NGX_OK) {
                    return NGX_CONF_OK;
                }

                if (rc == NGX_ERROR) {
                    return NGX_CONF_ERROR;
                }

                /* rc == NGX_BUSY */
                old = (ngx_http_variable_value_t *)
                        ngx_radix128tree_find(ucf->whitelist6,
                                              cidr.u.in6.addr.s6_addr);

                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "bot_protection duplicate \"%V\", old value: \"%v\"", &value[0], old);

                rc = ngx_radix128tree_delete(ucf->whitelist6,
                                             cidr.u.in6.addr.s6_addr,
                                             cidr.u.in6.mask.s6_addr);

                if (rc == NGX_ERROR) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_protection invalid radix tree");
                    return NGX_CONF_ERROR;
                }
            }

#endif

            /* fall through */
        default: /* AF_INET */

            cidr.u.in.addr = ntohl(cidr.u.in.addr);
            cidr.u.in.mask = ntohl(cidr.u.in.mask);

            for (i = 2; i; i--) {
                rc = ngx_radix32tree_insert(ucf->whitelist, cidr.u.in.addr, cidr.u.in.mask,
                                            (uintptr_t) &ngx_http_variable_true_value);
                if (rc == NGX_OK) {
                    return NGX_CONF_OK;
                }

                if (rc == NGX_ERROR) {
                    return NGX_CONF_ERROR;
                }

                /* rc == NGX_BUSY */
                old = (ngx_http_variable_value_t *)
                        ngx_radix32tree_find(ucf->whitelist, cidr.u.in.addr & cidr.u.in.mask);

                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "bot_protection duplicate \"%V\", old value: \"%v\"", &value[0], old);

                rc = ngx_radix32tree_delete(ucf->whitelist, cidr.u.in.addr, cidr.u.in.mask);

                if (rc == NGX_ERROR) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_protection invalid radix tree");
                    return NGX_CONF_ERROR;
                }
            }
    }

    return NGX_CONF_ERROR;
}

int
ngx_ishex(u_char *src, size_t len) {
    u_char c;

    if (len % 2) return 0;
    while (len--) {
        c = (*src++);
        if ((c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) continue;
        return 0;
    }

    return 1;
}

u_char *
ngx_hextobin(u_char *dst, u_char *src, size_t len) {
//#define hextobin(c) ((c) >= 'A' && (c) <= 'F' ? c - 'A' + 10 : (c) >= 'a' && (c) <= 'f' ? c - 'a' + 10 : c - '0')
    size_t i;

    if (len % 2) return NULL;
    for (i = 0; i < len / 2; i++) {
        *dst++ = hextobin(src[2 * i + 1]) + hextobin(src[2 * i]) * 16;
    }

    return dst;
}

static ngx_int_t
ngx_http_bot_protection_nocache(ngx_http_request_t *r) {
    ngx_uint_t i;
    ngx_table_elt_t *e, *cc, **ccp;

    e = r->headers_out.expires;
    if (e == NULL) {

        e = ngx_list_push(&r->headers_out.headers);
        if (e == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.expires = e;

        e->hash = 1;
        ngx_str_set(&e->key, "Expires");
    }

    e->value.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
    e->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";

    ccp = r->headers_out.cache_control.elts;
    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK) {
            return NGX_ERROR;
        }

        ccp = ngx_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return NGX_ERROR;
        }

        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return NGX_ERROR;
        }

        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    ngx_str_set(&cc->value, "no-cache");

    return NGX_OK;
}

static char *
ngx_http_bot_protection_refresh_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_bot_protection_conf_t *ucf = conf;

    ngx_int_t n;
    ngx_str_t *value;

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);
    if (n < 100 || n > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_protection invalid response code \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    ucf->refresh_status = n;

    return NGX_CONF_OK;
}