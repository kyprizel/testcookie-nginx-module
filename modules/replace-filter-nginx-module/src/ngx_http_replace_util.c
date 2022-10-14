
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_replace_util.h"


ngx_chain_t *
ngx_http_replace_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t     *cl;

    cl = ngx_chain_get_free_buf(p, free);
    if (cl == NULL) {
        return cl;
    }

    ngx_memzero(cl->buf, sizeof(ngx_buf_t));

    cl->buf->tag = (ngx_buf_tag_t) &ngx_http_replace_filter_module;

    return cl;
}


ngx_int_t
ngx_http_replace_split_chain(ngx_http_request_t *r, ngx_http_replace_ctx_t *ctx,
    ngx_chain_t **pa, ngx_chain_t ***plast_a, sre_int_t split, ngx_chain_t **pb,
    ngx_chain_t ***plast_b, unsigned b_sane)
{
    sre_int_t            file_last;
    ngx_chain_t         *cl, *newcl, **ll;

#if 0
    b_sane = 0;
#endif

    ll = pa;
    for (cl = *pa; cl; ll = &cl->next, cl = cl->next) {
        if (cl->buf->file_last > split) {
            /* found an overlap */

            if (cl->buf->file_pos < split) {

                dd("adjust cl buf (b_sane=%d): \"%.*s\"", b_sane,
                   (int) ngx_buf_size(cl->buf), cl->buf->pos);

                file_last = cl->buf->file_last;
                cl->buf->last -= file_last - split;
                cl->buf->file_last = split;

                dd("adjusted cl buf (next=%p): %.*s",
                   cl->next,
                   (int) ngx_buf_size(cl->buf), cl->buf->pos);

                /* build the b chain */
                if (b_sane) {
                    newcl = ngx_http_replace_get_free_buf(r->pool,
                                                          &ctx->free);
                    if (newcl == NULL) {
                        return NGX_ERROR;
                    }

                    newcl->buf->memory = 1;
                    newcl->buf->pos = cl->buf->last;
                    newcl->buf->last = cl->buf->last + file_last - split;
                    newcl->buf->file_pos = split;
                    newcl->buf->file_last = file_last;

                    newcl->next = cl->next;

                    *pb = newcl;
                    if (plast_b) {
                        if (cl->next) {
                            *plast_b = *plast_a;

                        } else {
                            *plast_b = &newcl->next;
                        }
                    }

                } else {
                    *pb = cl->next;
                    if (plast_b) {
                        *plast_b = *plast_a;
                    }
                }

                /* truncate the a chain */
                *plast_a = &cl->next;
                cl->next = NULL;

                return NGX_OK;
            }

            /* build the b chain */
            *pb = cl;
            if (plast_b) {
                *plast_b = *plast_a;
            }

            /* truncate the a chain */
            *plast_a = ll;
            *ll = NULL;

            return NGX_OK;
        }
    }

    /* missed */

    *pb = NULL;
    if (plast_b) {
        *plast_b = pb;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_replace_new_pending_buf(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, sre_int_t from, sre_int_t to,
    ngx_chain_t **out)
{
    size_t               len;
    ngx_buf_t           *b;
    ngx_chain_t         *cl;

    ngx_http_replace_loc_conf_t  *rlcf;

    if (from < ctx->stream_pos) {
        from = ctx->stream_pos;
    }

    len = (size_t) (to - from);
    if (len == 0) {
        return NGX_ERROR;
    }

    ctx->total_buffered += len;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_replace_filter_module);

    if (ctx->total_buffered > rlcf->max_buffered_size) {
#if 1
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "replace filter: exceeding "
                      "replace_filter_max_buffered_size (%uz): %uz",
                      rlcf->max_buffered_size, ctx->total_buffered);
        return NGX_BUSY;
#endif
    }

    cl = ngx_http_replace_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;
    b->temporary = 1;

    /* abuse the file_pos and file_last fields here */
    b->file_pos = from;
    b->file_last = to;

    b->start = ngx_palloc(r->pool, len);
    if (b->start == NULL) {
        return NGX_ERROR;
    }
    b->end = b->start + len;

    b->pos = b->start;
    b->last = ngx_copy(b->pos, ctx->buf->pos + from - ctx->stream_pos, len);

    dd("buffered pending data: stream_pos=%ld (%ld, %ld): %.*s",
       (long) ctx->stream_pos, (long) from, (long) to,
       (int) len, ctx->buf->pos + from - ctx->stream_pos);

    *out = cl;
    return NGX_OK;
}


#if (DDEBUG)
void
ngx_http_replace_dump_chain(const char *prefix, ngx_chain_t **pcl,
    ngx_chain_t **last)
{
    ngx_chain_t        *cl;

    if (*pcl == NULL) {
        dd("%s buf empty", prefix);
        if (last && last != pcl) {
            dd("BAD last %s", prefix);
            assert(0);
        }
    }

    for (cl = *pcl; cl; cl = cl->next) {
        dd("%s buf: \"%.*s\"", prefix, (int) ngx_buf_size(cl->buf),
           cl->buf->pos);

        if (cl->next == NULL) {
            if (last && last != &cl->next) {
                dd("BAD last %s", prefix);
                assert(0);
            }
        }
    }
}
#endif  /* DDEBUG */
