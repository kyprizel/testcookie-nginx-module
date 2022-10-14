
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_replace_filter_module.h"
#include "ngx_http_replace_parse.h"
#include "ngx_http_replace_script.h"
#include "ngx_http_replace_util.h"


enum {
    SREGEX_COMPILER_POOL_SIZE = 4096
};


static ngx_int_t ngx_http_replace_output(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx);
static char *ngx_http_replace_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_replace_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_replace_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_replace_filter_init(ngx_conf_t *cf);
static void ngx_http_replace_cleanup_pool(void *data);
static void *ngx_http_replace_create_main_conf(ngx_conf_t *cf);


#define ngx_http_replace_regex_is_disabled(ctx)                              \
    ((ctx)->disabled[(ctx)->regex_id / 8] & (1 << ((ctx)->regex_id % 8)))


#define ngx_http_replace_regex_set_disabled(ctx)                             \
    (ctx)->disabled[(ctx)->regex_id / 8] |= (1 << ((ctx)->regex_id % 8))


static volatile ngx_cycle_t  *ngx_http_replace_prev_cycle = NULL;


#define NGX_HTTP_REPLACE_CLEAR_LAST_MODIFIED    0
#define NGX_HTTP_REPLACE_KEEP_LAST_MODIFIED     1


static ngx_conf_enum_t  ngx_http_replace_filter_last_modified[] = {
    { ngx_string("clear"), NGX_HTTP_REPLACE_CLEAR_LAST_MODIFIED },
    { ngx_string("keep"), NGX_HTTP_REPLACE_KEEP_LAST_MODIFIED },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_replace_filter_commands[] = {

    { ngx_string("replace_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE23,
      ngx_http_replace_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("replace_filter_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_replace_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("replace_filter_max_buffered_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_replace_loc_conf_t, max_buffered_size),
      NULL },

    { ngx_string("replace_filter_last_modified"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_1MORE,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_replace_loc_conf_t, last_modified),
      &ngx_http_replace_filter_last_modified },

    { ngx_string("replace_filter_skip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
          |NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_replace_loc_conf_t, skip),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_replace_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_replace_filter_init,          /* postconfiguration */

    ngx_http_replace_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_replace_create_loc_conf,      /* create location configuration */
    ngx_http_replace_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_replace_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_replace_filter_module_ctx,   /* module context */
    ngx_http_replace_filter_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_replace_header_filter(ngx_http_request_t *r)
{
    size_t                         size;
    ngx_str_t                      skip;
    ngx_pool_cleanup_t            *cln;
    ngx_http_replace_ctx_t        *ctx;
    ngx_http_replace_loc_conf_t   *rlcf;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_replace_filter_module);

    dd("replace header filter");

    if (rlcf->regexes.nelts == 0
        || r->headers_out.content_length_n == 0
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || ngx_http_test_content_type(r, &rlcf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    dd("skip: %p", rlcf->skip);

    if (rlcf->skip != NULL) {
        if (ngx_http_complex_value(r, rlcf->skip, &skip) != NGX_OK) {
            return NGX_ERROR;
        }

        if (skip.len && (skip.len != 1 || skip.data[0] != '0')) {
            return ngx_http_next_header_filter(r);
        }
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_replace_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->last_special = &ctx->special;
    ctx->last_pending = &ctx->pending;
    ctx->last_pending2 = &ctx->pending2;
    ctx->last_captured = &ctx->captured;

    ctx->sub = ngx_pcalloc(r->pool,
                           rlcf->multi_replace.nelts * sizeof(ngx_str_t));
    if (ctx->sub == NULL) {
        return NGX_ERROR;
    }

    ctx->ovector = ngx_palloc(r->pool, rlcf->ovecsize);
    if (ctx->ovector == NULL) {
        return NGX_ERROR;
    }

    size = ngx_align(rlcf->regexes.nelts, 8) / 8;
    ctx->disabled = ngx_pcalloc(r->pool, size);
    if (ctx->disabled == NULL) {
        return NGX_ERROR;
    }

    ctx->vm_pool = sre_create_pool(1024);
    if (ctx->vm_pool == NULL) {
        return NGX_ERROR;
    }

    dd("created vm pool %p", ctx->vm_pool);

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        sre_destroy_pool(ctx->vm_pool);
        return NGX_ERROR;
    }

    cln->data = ctx->vm_pool;
    cln->handler = ngx_http_replace_cleanup_pool;

    ctx->vm_ctx = sre_vm_pike_create_ctx(ctx->vm_pool, rlcf->program,
                                         ctx->ovector, rlcf->ovecsize);
    if (ctx->vm_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_replace_filter_module);

    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);

        if (rlcf->last_modified == NGX_HTTP_REPLACE_CLEAR_LAST_MODIFIED) {
            ngx_http_clear_last_modified(r);
        }
    }

    return ngx_http_next_header_filter(r);
}


static void
ngx_http_replace_cleanup_pool(void *data)
{
    sre_pool_t          *pool = data;

    if (pool) {
        dd("destroy sre pool %p", pool);
        sre_destroy_pool(pool);
    }
}


static ngx_int_t
ngx_http_replace_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_str_t                 *sub;
    ngx_chain_t               *cl, *cur = NULL, *rematch = NULL;

    ngx_http_replace_ctx_t        *ctx;
    ngx_http_replace_loc_conf_t   *rlcf;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_replace_filter_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_replace_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    if ((ctx->once || ctx->vm_done) && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (ngx_http_replace_output(r, ctx) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http sub filter \"%V\"", &r->uri);

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL) {
            cur = ctx->in;
            ctx->buf = cur->buf;
            ctx->in = cur->next;

            ctx->pos = ctx->buf->pos;
            ctx->special_buf = ngx_buf_special(ctx->buf);
            ctx->last_buf = (ctx->buf->last_buf || ctx->buf->last_in_chain);

            dd("=== new incoming buf: size=%d, special=%u, last=%u",
               (int) ngx_buf_size(ctx->buf), ctx->special_buf,
               ctx->last_buf);
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last
               || (ctx->special_buf && ctx->last_buf))
        {
            rc = rlcf->parse_buf(r, ctx, rematch);

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "replace filter parse: %d, %p-%p",
                           rc, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (rc == NGX_DECLINED) {

                if (ctx->pending) {
                    *ctx->last_out = ctx->pending;
                    ctx->last_out = ctx->last_pending;

                    ctx->pending = NULL;
                    ctx->last_pending = &ctx->pending;
                }

                if (!ctx->special_buf) {
                    ctx->copy_start = ctx->pos;
                    ctx->copy_end = ctx->buf->last;
                    ctx->pos = ctx->buf->last;

                } else {
                    ctx->copy_start = NULL;
                    ctx->copy_end = NULL;
                }

                sre_reset_pool(ctx->vm_pool);
                ctx->vm_done = 1;
            }

            dd("copy_end - copy_start: %d, special: %u",
               (int) (ctx->copy_end - ctx->copy_start), ctx->special_buf);

            if (ctx->copy_start != ctx->copy_end && !ctx->special_buf) {
                dd("copy: %.*s", (int) (ctx->copy_end - ctx->copy_start),
                   ctx->copy_start);

                cl = ngx_http_replace_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;

                b->memory = 1;
                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (rc == NGX_AGAIN) {
                if (ctx->special_buf && ctx->last_buf) {
                    break;
                }

                continue;
            }

            if (rc == NGX_DECLINED) {
                break;
            }

            /* rc == NGX_OK || rc == NGX_BUSY */

            cl = ngx_http_replace_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            dd("free data buf: %p", b);

            sub = &ctx->sub[ctx->regex_id];

            if (sub->data == NULL
                || rlcf->parse_buf == ngx_http_replace_capturing_parse)
            {
                ngx_http_replace_complex_value_t            *cv;

                if (ngx_http_replace_regex_is_disabled(ctx)) {
                    cv = &rlcf->verbatim;

                } else {
                    cv = rlcf->multi_replace.elts;
                    cv = &cv[ctx->regex_id];
                }

                if (ngx_http_replace_complex_value(r, ctx->captured,
                                                   rlcf->ncaps,
                                                   ctx->ovector,
                                                   cv, sub)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                /* release ctx->captured */
                if (ctx->captured) {
                    dd("release ctx captured: %p", ctx->captured);
                    *ctx->last_captured = ctx->free;
                    ctx->free = ctx->captured;

                    ctx->captured = NULL;
                    ctx->last_captured = &ctx->captured;
                }
            }

            dd("emit replaced value: \"%.*s\"", (int) sub->len, sub->data);

            if (sub->len) {
                b->memory = 1;
                b->pos = sub->data;
                b->last = sub->data + sub->len;

            } else {
                b->sync = 1;
            }

            cl->buf = b;
            cl->next = NULL;

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            if (!ctx->once && !ngx_http_replace_regex_is_disabled(ctx)) {
                uint8_t    *once;

                once = rlcf->multi_once.elts;

                if (rlcf->regexes.nelts == 1) {
                    ctx->once = once[0];

                } else {
                    if (once[ctx->regex_id]) {
                        ngx_http_replace_regex_set_disabled(ctx);
                        if (!rlcf->seen_global
                            && ++ctx->disabled_count == rlcf->regexes.nelts)
                        {
                            ctx->once = 1;
                        }
                    }
                }
            }

            if (rc == NGX_BUSY) {
                dd("goto rematch");
                goto rematch;
            }

            if (ctx->special_buf) {
                break;
            }

            continue;
        }

        if ((ctx->buf->flush || ctx->last_buf || ngx_buf_in_memory(ctx->buf))
            && cur)
        {
            if (b == NULL) {
                cl = ngx_http_replace_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                b = cl->buf;
                b->sync = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            dd("setting shadow and last buf: %d", (int) ctx->buf->last_buf);
            b->last_buf = ctx->buf->last_buf;
            b->last_in_chain = ctx->buf->last_in_chain;
            b->flush = ctx->buf->flush;
            b->shadow = ctx->buf;
            b->recycled = ctx->buf->recycled;
        }

        if (!ctx->special_buf) {
            ctx->stream_pos += ctx->buf->last - ctx->buf->pos;
        }

        if (rematch) {
            rematch->next = ctx->free;
            ctx->free = rematch;
            rematch = NULL;
        }

rematch:

        dd("ctx->rematch: %p", ctx->rematch);

        if (ctx->rematch == NULL) {
            ctx->buf = NULL;
            cur = NULL;

        } else {

            if (cur) {
                ctx->in = cur;
                cur = NULL;
            }

            ctx->buf = ctx->rematch->buf;

            dd("ctx->buf set to rematch buf %p, len=%d, next=%p",
               ctx->buf, (int) ngx_buf_size(ctx->buf), ctx->rematch->next);

            rematch = ctx->rematch;
            ctx->rematch = rematch->next;

            ctx->pos = ctx->buf->pos;
            ctx->special_buf = ngx_buf_special(ctx->buf);
            ctx->last_buf = (ctx->buf->last_buf || ctx->buf->last_in_chain);
            ctx->stream_pos = ctx->buf->file_pos;
        }

#if (DDEBUG)
        /*
        ngx_http_replace_dump_chain("ctx->pending", &ctx->pending,
                                    ctx->last_pending);
        ngx_http_replace_dump_chain("ctx->pending2", &ctx->pending2,
                                    ctx->last_pending2);
        */
#endif
    } /* while */

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_replace_output(r, ctx);
}


static ngx_int_t
ngx_http_replace_output(ngx_http_request_t *r, ngx_http_replace_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

#if (DDEBUG)
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "replace out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }

    /* ngx_http_replace_dump_chain("ctx->out", &ctx->out, ctx->last_out); */
#endif

    rc = ngx_http_next_body_filter(r, ctx->out);

    /* we are essentially duplicating the logic of
     * ngx_chain_update_chains below,
     * with our own optimizations */

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

        if (cl->buf->tag != (ngx_buf_tag_t) &ngx_http_replace_filter_module) {
            ctx->busy = cl->next;
            ngx_free_chain(r->pool, cl);
            continue;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
            b->shadow->file_pos = b->shadow->file_last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_special(b)) {

            /* collect special bufs to ctx->special, which may still be busy */

            cl->next = NULL;
            *ctx->last_special = cl;
            ctx->last_special = &cl->next;

        } else {

            /* add ctx->special to ctx->free because they cannot be busy at
             * this point */

            *ctx->last_special = ctx->free;
            ctx->free = ctx->special;
            ctx->special = NULL;
            ctx->last_special = &ctx->special;

#if 0
            /* free the temporary buf's data block if it is big enough */
            if (b->temporary
                && b->start != NULL
                && b->end - b->start > (ssize_t) r->pool->max)
            {
                ngx_pfree(r->pool, b->start);
            }
#endif

            /* add the data buf itself to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static char *
ngx_http_replace_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_replace_loc_conf_t     *rlcf = conf;
    ngx_http_replace_main_conf_t    *rmcf;

    int             *flags;
    u_char          *p, **re;
    ngx_str_t       *value;
    ngx_uint_t       i;
    uint8_t         *once;

    ngx_pool_cleanup_t                          *cln;
    ngx_http_replace_complex_value_t            *cv;
    ngx_http_replace_compile_complex_value_t     ccv;

    value = cf->args->elts;

    re = ngx_array_push(&rlcf->regexes);
    if (re == NULL) {
        return NGX_CONF_ERROR;
    }

    *re = value[1].data;

    cv = ngx_array_push(&rlcf->multi_replace);
    if (cv == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(cv, sizeof(ngx_http_replace_complex_value_t));
    ngx_memzero(&ccv, sizeof(ngx_http_replace_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = cv;

    if (ngx_http_replace_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* check variable usage in the "replace" argument */

    if (cv->capture_variables) {
        rlcf->parse_buf = ngx_http_replace_capturing_parse;

    } else if (rlcf->parse_buf == NULL) {
        rlcf->parse_buf = ngx_http_replace_non_capturing_parse;
    }

#if 0
    rlcf->parse_buf = ngx_http_replace_capturing_parse;
#endif

    flags = ngx_array_push(&rlcf->multi_flags);
    if (flags == NULL) {
        return NGX_CONF_ERROR;
    }
    *flags = 0;

    once = ngx_array_push(&rlcf->multi_once);
    if (once == NULL) {
        return NGX_CONF_ERROR;
    }
    *once = 1;  /* default to once */

    if (cf->args->nelts == 4) {
        /* 3 user args */

        p = value[3].data;

        for (i = 0; i < value[3].len; i++) {
            switch (p[i]) {
            case 'i':
                *flags |= SRE_REGEX_CASELESS;
                break;

            case 'g':
                *once = 0;
                break;

            default:
                return "specifies an unrecognized regex flag";
            }
        }
    }

    if (*once) {
        rlcf->seen_once = 1;

    } else {
        rlcf->seen_global = 1;
    }

    if (rlcf->seen_once && rlcf->regexes.nelts > 1) {
        rlcf->parse_buf = ngx_http_replace_capturing_parse;

        if (rlcf->verbatim.value.data == NULL) {
            ngx_str_t           v = ngx_string("$&");

            ngx_memzero(&ccv, sizeof(ngx_http_replace_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &v;
            ccv.complex_value = &rlcf->verbatim;

            if (ngx_http_replace_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    rmcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_replace_filter_module);

    if (rmcf->compiler_pool == NULL) {
        rmcf->compiler_pool = sre_create_pool(SREGEX_COMPILER_POOL_SIZE);
        if (rmcf->compiler_pool == NULL) {
            return NGX_CONF_ERROR;
        }

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            sre_destroy_pool(rmcf->compiler_pool);
            rmcf->compiler_pool = NULL;
            return NGX_CONF_ERROR;
        }

        cln->data = rmcf->compiler_pool;
        cln->handler = ngx_http_replace_cleanup_pool;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_replace_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_replace_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_replace_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->program = NULL;
     *     conf->ncaps = 0;
     *     conf->ovecsize = 0;
     *     conf->parse_buf = NULL;
     *     conf->verbatim = { {0, NULL}, NULL, NULL, 0 };
     *     conf->seen_once = 0;
     *     conf->seen_global = 0;
     *     conf->skip = NULL;
     */

    conf->max_buffered_size = NGX_CONF_UNSET_SIZE;
    conf->last_modified = NGX_CONF_UNSET_UINT;

    ngx_array_init(&conf->multi_replace, cf->pool, 4,
                   sizeof(ngx_http_replace_complex_value_t));

    ngx_array_init(&conf->multi_flags, cf->pool, 4, sizeof(int));

    ngx_array_init(&conf->regexes, cf->pool, 4, sizeof(u_char *));

    ngx_array_init(&conf->multi_once, cf->pool, 4, sizeof(uint8_t));

    return conf;
}


static char *
ngx_http_replace_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    u_char         **value;
    sre_int_t        err_offset, err_regex_id;
    ngx_str_t        prefix, suffix;
    sre_pool_t      *ppool; /* parser pool */
    sre_regex_t     *re;
    sre_program_t   *prog;

    ngx_http_replace_main_conf_t    *rmcf;

    ngx_http_replace_loc_conf_t *prev = parent;
    ngx_http_replace_loc_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->max_buffered_size,
                              prev->max_buffered_size,
                              8192);

    ngx_conf_merge_uint_value(conf->last_modified,
                              prev->last_modified,
                              NGX_HTTP_REPLACE_CLEAR_LAST_MODIFIED);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->skip == NULL) {
        conf->skip = prev->skip;
    }

    if (conf->regexes.nelts > 0 && conf->program == NULL) {

        dd("parsing and compiling %d regexes", (int) conf->regexes.nelts);

        ppool = sre_create_pool(1024);
        if (ppool == NULL) {
            return NGX_CONF_ERROR;
        }

        value = conf->regexes.elts;

        re = sre_regex_parse_multi(ppool, value, conf->regexes.nelts,
                                   &conf->ncaps, conf->multi_flags.elts,
                                   &err_offset, &err_regex_id);

        if (re == NULL) {

            if (err_offset >= 0) {
                prefix.data = value[err_regex_id];
                prefix.len = err_offset;

                suffix.data = value[err_regex_id] + err_offset;
                suffix.len = ngx_strlen(value[err_regex_id]) - err_offset;

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "failed to parse regex at offset %i: "
                                   "syntax error; marked by <-- HERE in "
                                   "\"%V <-- HERE %V\"",
                                   (ngx_int_t) err_offset, &prefix, &suffix);

            } else {

                if (err_regex_id >= 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "failed to parse regex \"%s\"",
                                       value[err_regex_id]);

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "failed to parse regex \"%s\" "
                                       "and its siblings",
                                       value[0]);
                }
            }

            sre_destroy_pool(ppool);
            return NGX_CONF_ERROR;
        }

        rmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_replace_filter_module);

        prog = sre_regex_compile(rmcf->compiler_pool, re);

        sre_destroy_pool(ppool);

        if (prog == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "failed to compile regex \"%s\" and its "
                               "siblings", value[0]);

            return NGX_CONF_ERROR;
        }

        conf->program = prog;
        conf->ovecsize = 2 * (conf->ncaps + 1) * sizeof(sre_int_t);

    } else {

        conf->regexes       = prev->regexes;
        conf->multi_once    = prev->multi_once;
        conf->multi_flags   = prev->multi_flags;
        conf->multi_replace = prev->multi_replace;
        conf->parse_buf     = prev->parse_buf;
        conf->verbatim      = prev->verbatim;
        conf->program       = prev->program;
        conf->ncaps         = prev->ncaps;
        conf->ovecsize      = prev->ovecsize;
        conf->seen_once     = prev->seen_once;
        conf->seen_global   = prev->seen_global;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_replace_filter_init(ngx_conf_t *cf)
{
    int                              multi_http_blocks;
    ngx_http_replace_main_conf_t    *rmcf;

    rmcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_replace_filter_module);

    if (ngx_http_replace_prev_cycle != ngx_cycle) {
        ngx_http_replace_prev_cycle = ngx_cycle;
        multi_http_blocks = 0;

    } else {
        multi_http_blocks = 1;
    }

    if (multi_http_blocks || rmcf->compiler_pool != NULL) {
        ngx_http_next_header_filter = ngx_http_top_header_filter;
        ngx_http_top_header_filter = ngx_http_replace_header_filter;

        ngx_http_next_body_filter = ngx_http_top_body_filter;
        ngx_http_top_body_filter = ngx_http_replace_body_filter;

        return NGX_OK;
    }

    return NGX_OK;
}


static void *
ngx_http_replace_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_replace_main_conf_t    *rmcf;

    rmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_replace_main_conf_t));
    if (rmcf == NULL) {
        return NULL;
    }

    /* set by ngx_pcalloc:
     *      rmcf->compiler_pool = NULL;
     */

    return rmcf;
}
