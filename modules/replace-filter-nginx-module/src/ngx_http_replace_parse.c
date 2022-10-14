
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_replace_parse.h"
#include "ngx_http_replace_util.h"


static void ngx_http_replace_check_total_buffered(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, sre_int_t len, sre_int_t mlen);


ngx_int_t
ngx_http_replace_capturing_parse(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, ngx_chain_t *rematch)
{
    sre_int_t              ret, from, to;
    ngx_int_t              rc;
    ngx_chain_t           *new_rematch = NULL;
    ngx_chain_t           *cl;
    ngx_chain_t          **last_rematch, **last;
    size_t                 len;

    dd("replace capturing parse");

    if (ctx->once || ctx->vm_done) {
        ctx->copy_start = ctx->pos;
        ctx->copy_end = ctx->buf->last;
        ctx->pos = ctx->buf->last;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "once");

        return NGX_AGAIN;
    }

    len = ctx->buf->last - ctx->pos;

    dd("=== process data chunk %p len=%d, pos=%u, special=%u, "
       "last=%u, \"%.*s\"", ctx->buf, (int) (ctx->buf->last - ctx->pos),
       (int) (ctx->pos - ctx->buf->pos + ctx->stream_pos),
       ctx->special_buf, ctx->last_buf,
       (int) (ctx->buf->last - ctx->pos), ctx->pos);

    ret = sre_vm_pike_exec(ctx->vm_ctx, ctx->pos, len, ctx->last_buf, NULL);

    dd("vm pike exec: %d", (int) ret);

    if (ret >= 0) {
        ctx->regex_id       = ret;
        ctx->total_buffered = 0;

        from = ctx->ovector[0];
        to = ctx->ovector[1];

        dd("pike vm ok: (%d, %d)", (int) from, (int) to);

        if (from >= ctx->stream_pos) {
            /* the match is completely on the current buf */

            if (ctx->pending) {
                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            /* prepare ctx->captured */

            cl = ngx_http_replace_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf->pos = ctx->buf->pos;
            cl->buf->last = ctx->buf->last;
            cl->buf->memory = 1;
            cl->buf->file_pos = ctx->stream_pos;
            cl->buf->file_last = ctx->stream_pos
                                 + (cl->buf->last - cl->buf->pos);

            *ctx->last_captured = cl;
            ctx->last_captured = &cl->next;

            dd("ctx captured: %p", ctx->captured);

            /* prepare copy-out data */

            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->buf->pos + (from - ctx->stream_pos);

            dd("copy len: %d", (int) (ctx->copy_end - ctx->copy_start));

            ctx->pos = ctx->buf->pos + (to - ctx->stream_pos);
            return NGX_OK;
        }

        /* from < ctx->stream_pos */

        if (ctx->pending) {

            if (ngx_http_replace_split_chain(r, ctx, &ctx->pending,
                                             &ctx->last_pending, from,
                                             &cl, &last, 1)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (ctx->pending) {
                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            if (cl) {
                if (to >= ctx->stream_pos) {
                    /* no pending data to be rematched */

                    if (to == ctx->stream_pos) {
                        *ctx->last_captured = cl;
                        ctx->last_captured = &cl->next;

                    } else {
                        *ctx->last_captured = cl;
                        ctx->last_captured = last;

                        cl = ngx_http_replace_get_free_buf(r->pool, &ctx->free);
                        if (cl == NULL) {
                            return NGX_ERROR;
                        }

                        cl->buf->pos = ctx->buf->pos;
                        cl->buf->last = ctx->buf->last;
                        cl->buf->memory = 1;
                        cl->buf->file_pos = ctx->stream_pos;
                        cl->buf->file_last = ctx->stream_pos
                                             + (cl->buf->last - cl->buf->pos);

                        *ctx->last_captured = cl;
                        ctx->last_captured = &cl->next;
                    }

                } else {
                    /* there's pending data to be rematched */

                    if (ngx_http_replace_split_chain(r, ctx, &cl,
                                                     &last,
                                                     to, &new_rematch,
                                                     &last_rematch, 1)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    if (cl) {
                        *ctx->last_captured = cl;
                        ctx->last_captured = last;
                    }

                    if (new_rematch) {
                        if (rematch) {
                            ctx->rematch = rematch;
                        }

                        /* prepend cl to ctx->rematch */
                        *last_rematch = ctx->rematch;
                        ctx->rematch = new_rematch;
                    }
                }
            }
        }

#if (DDEBUG)
        ngx_http_replace_dump_chain("ctx->rematch", &ctx->rematch, NULL);
#endif

        ctx->copy_start = NULL;
        ctx->copy_end = NULL;

        ctx->pos = ctx->buf->pos + (to - ctx->stream_pos);

        return new_rematch ? NGX_BUSY : NGX_OK;
    }

    switch (ret) {
    case SRE_AGAIN:
        from = ctx->ovector[0];
        to = ctx->ovector[1];

        dd("pike vm again: (%d, %d)", (int) from, (int) to);

        if (from == -1) {
            from = ctx->stream_pos + (ctx->buf->last - ctx->buf->pos);
        }

        if (to == -1) {
            to = ctx->stream_pos + (ctx->buf->last - ctx->buf->pos);
        }

        dd("pike vm again (adjusted): stream pos:%d, (%d, %d)",
           (int) ctx->stream_pos, (int) from, (int) to);

        if (from > to) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "invalid capture range: %i > %i", (ngx_int_t) from,
                          (ngx_int_t) to);
            return NGX_ERROR;
        }

        if (from == to) {
            if (ctx->pending) {
                ctx->total_buffered = 0;

                dd("output pending");
                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->buf->pos + (from - ctx->stream_pos);
            ctx->pos = ctx->copy_end;

            return NGX_AGAIN;
        }

        /*
         * append the existing ctx->pending data right before
         * the $& capture to ctx->out.
         */

        if (from >= ctx->stream_pos) {
            /* the match is completely on the current buf */

            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->buf->pos + (from - ctx->stream_pos);

            if (ctx->pending) {
                ctx->total_buffered = 0;

                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            dd("create ctx->pending as (%ld, %ld)", (long) from, (long) to);
            rc = ngx_http_replace_new_pending_buf(r, ctx, from, to, &cl);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

#if 1
            if (rc == NGX_BUSY) {
                dd("stop processing because of buffer size limit reached");
                ctx->once = 1;
                ctx->copy_start = ctx->pos;
                ctx->copy_end = ctx->buf->last;
                ctx->pos = ctx->buf->last;
                return NGX_AGAIN;
            }
#endif

            *ctx->last_pending = cl;
            ctx->last_pending = &cl->next;

            ctx->pos = ctx->buf->last;

            return NGX_AGAIN;
        }

        dd("from < ctx->stream_pos");

        if (ctx->pending) {
            /* split ctx->pending into ctx->out and ctx->pending */

            if (ngx_http_replace_split_chain(r, ctx, &ctx->pending,
                                             &ctx->last_pending, from, &cl,
                                             &last, 1)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (ctx->pending) {
                dd("adjust pending: pos=%d, from=%d",
                   (int) ctx->pending->buf->file_pos, (int) from);

                ctx->total_buffered -= (size_t)
                    (from - ctx->pending->buf->file_pos);

                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            if (cl) {
                dd("splitted ctx->pending into ctx->out and ctx->pending: %d",
                   (int) ctx->total_buffered);

                ctx->pending = cl;
                ctx->last_pending = last;
            }
        }

        /* new pending data to buffer to ctx->pending */

        rc = ngx_http_replace_new_pending_buf(r, ctx, ctx->pos
                                              - ctx->buf->pos
                                              + ctx->stream_pos, to, &cl);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

#if 1
        if (rc == NGX_BUSY) {
            ctx->once = 1;

            if (ctx->pending) {
                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->buf->last;
            ctx->pos = ctx->buf->last;

            return NGX_AGAIN;
        }
#endif

        *ctx->last_pending = cl;
        ctx->last_pending = &cl->next;

        ctx->copy_start = NULL;
        ctx->copy_end = NULL;

        ctx->pos = ctx->buf->last;

        return NGX_AGAIN;

    case SRE_DECLINED:
        ctx->total_buffered = 0;

        return NGX_DECLINED;

    default:
        /* SRE_ERROR */
        return NGX_ERROR;
    }

    /* cannot reach here */
}


ngx_int_t
ngx_http_replace_non_capturing_parse(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, ngx_chain_t *rematch)
{
    sre_int_t              ret, from, to, mfrom = -1, mto = -1;
    ngx_int_t              rc;
    ngx_chain_t           *new_rematch = NULL;
    ngx_chain_t           *cl;
    ngx_chain_t          **last_rematch, **last;
    size_t                 len;
    sre_int_t             *pending_matched;

    dd("replace non capturing parse");

    if (ctx->once || ctx->vm_done) {
        ctx->copy_start = ctx->pos;
        ctx->copy_end = ctx->buf->last;
        ctx->pos = ctx->buf->last;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "once");

        return NGX_AGAIN;
    }

    len = ctx->buf->last - ctx->pos;

    dd("=== process data chunk %p len=%d, pos=%u, special=%u, "
       "last=%u, \"%.*s\"", ctx->buf, (int) (ctx->buf->last - ctx->pos),
       (int) (ctx->pos - ctx->buf->pos + ctx->stream_pos),
       ctx->special_buf, ctx->last_buf,
       (int) (ctx->buf->last - ctx->pos), ctx->pos);

    ret = sre_vm_pike_exec(ctx->vm_ctx, ctx->pos, len, ctx->last_buf,
                           &pending_matched);

    dd("vm pike exec: %d", (int) ret);

    if (ret >= 0) {
        ctx->regex_id = ret;
        ctx->total_buffered = 0;

        from = ctx->ovector[0];
        to = ctx->ovector[1];

        dd("pike vm ok: (%d, %d)", (int) from, (int) to);

        if (from >= ctx->stream_pos) {
            /* the match is completely on the current buf */

            if (ctx->pending) {
                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            if (ctx->pending2) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "assertion failed: ctx->pending2 is not NULL "
                              "when the match is completely on the current "
                              "buf");
                return NGX_ERROR;
            }

            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->buf->pos + (from - ctx->stream_pos);

            dd("copy len: %d", (int) (ctx->copy_end - ctx->copy_start));

            ctx->pos = ctx->buf->pos + (to - ctx->stream_pos);
            return NGX_OK;
        }

        /* from < ctx->stream_pos */

        if (ctx->pending) {

            if (ngx_http_replace_split_chain(r, ctx, &ctx->pending,
                                             &ctx->last_pending, from,
                                             &cl, &last, 0)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (ctx->pending) {
                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            if (cl) {
                *last = ctx->free;
                ctx->free = cl;
            }
        }

        if (ctx->pending2) {

            if (ngx_http_replace_split_chain(r, ctx, &ctx->pending2,
                                             &ctx->last_pending2,
                                             to, &new_rematch, &last_rematch, 1)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (ctx->pending2) {
                *ctx->last_pending2 = ctx->free;
                ctx->free = ctx->pending2;

                ctx->pending2 = NULL;
                ctx->last_pending2 = &ctx->pending2;
            }

            if (new_rematch) {
                if (rematch) {
                    ctx->rematch = rematch;
                }

                /* prepend cl to ctx->rematch */
                *last_rematch = ctx->rematch;
                ctx->rematch = new_rematch;
            }
        }

#if (DDEBUG)
        ngx_http_replace_dump_chain("ctx->rematch", &ctx->rematch, NULL);
#endif

        ctx->copy_start = NULL;
        ctx->copy_end = NULL;

        ctx->pos = ctx->buf->pos + (to - ctx->stream_pos);

        return new_rematch ? NGX_BUSY : NGX_OK;
    }

    switch (ret) {
    case SRE_AGAIN:
        from = ctx->ovector[0];
        to = ctx->ovector[1];

        dd("pike vm again: (%d, %d)", (int) from, (int) to);

        if (from == -1) {
            from = ctx->stream_pos + (ctx->buf->last - ctx->buf->pos);
        }

        if (to == -1) {
            to = ctx->stream_pos + (ctx->buf->last - ctx->buf->pos);
        }

        dd("pike vm again (adjusted): stream pos:%d, (%d, %d)",
           (int) ctx->stream_pos, (int) from, (int) to);

        if (from > to) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "invalid capture range: %i > %i", (ngx_int_t) from,
                          (ngx_int_t) to);
            return NGX_ERROR;
        }

        if (pending_matched) {
            mfrom = pending_matched[0];
            mto = pending_matched[1];

            dd("pending matched: (%ld, %ld)", (long) mfrom, (long) mto);
        }

        if (from == to) {
            if (ctx->pending) {
                ctx->total_buffered = 0;

                dd("output pending");
                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->buf->pos + (from - ctx->stream_pos);
            ctx->pos = ctx->copy_end;

            ngx_http_replace_check_total_buffered(r, ctx, to - from,
                                                  mto - mfrom);
            return NGX_AGAIN;
        }

        /*
         * append the existing ctx->pending data right before
         * the $& capture to ctx->out.
         */

        if (from >= ctx->stream_pos) {
            /* the match is completely on the current buf */

            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->buf->pos + (from - ctx->stream_pos);

            if (ctx->pending) {
                ctx->total_buffered = 0;

                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            if (ctx->pending2) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "assertion failed: ctx->pending2 is not NULL "
                              "when the match is completely on the current "
                              "buf");
                return NGX_ERROR;
            }

            if (pending_matched) {

                if (from < mfrom) {
                    /* create ctx->pending as (from, mfrom) */

                    rc = ngx_http_replace_new_pending_buf(r, ctx, from, mfrom,
                                                          &cl);
                    if (rc == NGX_ERROR) {
                        return NGX_ERROR;
                    }

                    if (rc == NGX_BUSY) {
                        dd("stop processing because of buffer size limit "
                           "reached");
                        ctx->once = 1;
                        ctx->copy_start = ctx->pos;
                        ctx->copy_end = ctx->buf->last;
                        ctx->pos = ctx->buf->last;
                        return NGX_AGAIN;
                    }

                    *ctx->last_pending = cl;
                    ctx->last_pending = &cl->next;
                }

                if (mto < to) {
                    /* create ctx->pending2 as (mto, to) */
                    rc = ngx_http_replace_new_pending_buf(r, ctx, mto, to, &cl);
                    if (rc == NGX_ERROR) {
                        return NGX_ERROR;
                    }

#if 1
                    if (rc == NGX_BUSY) {
                        dd("stop processing because of buffer size limit "
                           "reached");
                        ctx->once = 1;
                        ctx->copy_start = ctx->pos;
                        ctx->copy_end = ctx->buf->last;
                        ctx->pos = ctx->buf->last;
                        return NGX_AGAIN;
                    }
#endif

                    *ctx->last_pending2 = cl;
                    ctx->last_pending2 = &cl->next;
                }

            } else {
                dd("create ctx->pending as (%ld, %ld)", (long) from, (long) to);
                rc = ngx_http_replace_new_pending_buf(r, ctx, from, to, &cl);
                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

#if 1
                if (rc == NGX_BUSY) {
                    dd("stop processing because of buffer size limit reached");
                    ctx->once = 1;
                    ctx->copy_start = ctx->pos;
                    ctx->copy_end = ctx->buf->last;
                    ctx->pos = ctx->buf->last;
                    return NGX_AGAIN;
                }
#endif

                *ctx->last_pending = cl;
                ctx->last_pending = &cl->next;
            }

            ctx->pos = ctx->buf->last;

            ngx_http_replace_check_total_buffered(r, ctx, to - from,
                                                  mto - mfrom);

            return NGX_AGAIN;
        }

        dd("from < ctx->stream_pos");

        if (ctx->pending) {
            /* split ctx->pending into ctx->out and ctx->pending */

            if (ngx_http_replace_split_chain(r, ctx, &ctx->pending,
                                             &ctx->last_pending, from, &cl,
                                             &last, 1)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (ctx->pending) {
                dd("adjust pending: pos=%d, from=%d",
                   (int) ctx->pending->buf->file_pos, (int) from);

                ctx->total_buffered -= (size_t)
                    (from - ctx->pending->buf->file_pos);

                *ctx->last_out = ctx->pending;
                ctx->last_out = ctx->last_pending;

                ctx->pending = NULL;
                ctx->last_pending = &ctx->pending;
            }

            if (cl) {
                dd("splitted ctx->pending into ctx->out and ctx->pending: %d",
                   (int) ctx->total_buffered);
                ctx->pending = cl;
                ctx->last_pending = last;
            }

            if (pending_matched && !ctx->pending2 && mto >= ctx->stream_pos) {
                dd("splitting ctx->pending into ctx->pending and ctx->free");

                if (ngx_http_replace_split_chain(r, ctx, &ctx->pending,
                                                 &ctx->last_pending, mfrom, &cl,
                                                 &last, 0)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                if (cl) {
                    ctx->total_buffered -= (size_t) (ctx->stream_pos - mfrom);

                    dd("splitted ctx->pending into ctx->pending and ctx->free");
                    *last = ctx->free;
                    ctx->free = cl;
                }
            }
        }

        if (ctx->pending2) {

            if (pending_matched) {
                dd("splitting ctx->pending2 into ctx->free and ctx->pending2");

                if (ngx_http_replace_split_chain(r, ctx, &ctx->pending2,
                                                 &ctx->last_pending2,
                                                 mto, &cl, &last, 1)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                if (ctx->pending2) {

                    dd("total buffered reduced by %d (was %d)",
                       (int) (mto - ctx->pending2->buf->file_pos),
                       (int) ctx->total_buffered);

                    ctx->total_buffered -= (size_t)
                        (mto - ctx->pending2->buf->file_pos);

                    *ctx->last_pending2 = ctx->free;
                    ctx->free = ctx->pending2;

                    ctx->pending2 = NULL;
                    ctx->last_pending2 = &ctx->pending2;
                }

                if (cl) {
                    ctx->pending2 = cl;
                    ctx->last_pending2 = last;
                }
            }

            if (mto < to) {
                dd("new pending data to buffer to ctx->pending2: (%ld, %ld)",
                   (long) mto, (long) to);

                rc = ngx_http_replace_new_pending_buf(r, ctx, mto, to, &cl);
                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

#if 1
                if (rc == NGX_BUSY) {
                    ctx->once = 1;

                    if (ctx->pending) {
                        *ctx->last_out = ctx->pending;
                        ctx->last_out = ctx->last_pending;

                        ctx->pending = NULL;
                        ctx->last_pending = &ctx->pending;
                    }

                    ctx->copy_start = NULL;
                    ctx->copy_end = NULL;

                    if (ctx->pending2) {
                        new_rematch = ctx->pending2;
                        last_rematch = ctx->last_pending2;

                        if (rematch) {
                            ctx->rematch = rematch;
                        }

                        /* prepend cl to ctx->rematch */
                        *last_rematch = ctx->rematch;
                        ctx->rematch = new_rematch;

                        ctx->pending2 = NULL;
                        ctx->last_pending2 = &ctx->pending2;
                    }

                    ctx->pos = ctx->buf->pos + (mto - ctx->stream_pos);
                    return new_rematch ? NGX_BUSY : NGX_OK;
                }
#endif

                *ctx->last_pending2 = cl;
                ctx->last_pending2 = &cl->next;
            }

            ctx->copy_start = NULL;
            ctx->copy_end = NULL;

            ctx->pos = ctx->buf->last;

            ngx_http_replace_check_total_buffered(r, ctx, to - from,
                                                  mto - mfrom);

            return NGX_AGAIN;
        }

        /* ctx->pending2 == NULL */

        if (pending_matched) {

            if (mto < to) {
                /* new pending data to buffer to ctx->pending2 */
                rc = ngx_http_replace_new_pending_buf(r, ctx, mto, to, &cl);
                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc == NGX_BUSY) {
                    ctx->once = 1;

                    if (ctx->pending) {
                        *ctx->last_out = ctx->pending;
                        ctx->last_out = ctx->last_pending;

                        ctx->pending = NULL;
                        ctx->last_pending = &ctx->pending;
                    }

                    ctx->copy_start = NULL;
                    ctx->copy_end = NULL;
                    ctx->pos = ctx->buf->pos + mto - ctx->stream_pos;

                    return NGX_OK;
                }

                *ctx->last_pending2 = cl;
                ctx->last_pending2 = &cl->next;
            }

            /* otherwise no new data to buffer */

        } else {

            /* new pending data to buffer to ctx->pending */
            rc = ngx_http_replace_new_pending_buf(r, ctx, ctx->pos
                                                  - ctx->buf->pos
                                                  + ctx->stream_pos, to, &cl);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

#if 1
            if (rc == NGX_BUSY) {
                ctx->once = 1;

                if (ctx->pending) {
                    *ctx->last_out = ctx->pending;
                    ctx->last_out = ctx->last_pending;

                    ctx->pending = NULL;
                    ctx->last_pending = &ctx->pending;
                }

                ctx->copy_start = ctx->pos;
                ctx->copy_end = ctx->buf->last;
                ctx->pos = ctx->buf->last;

                return NGX_AGAIN;
            }
#endif

            *ctx->last_pending = cl;
            ctx->last_pending = &cl->next;
        }

        ctx->copy_start = NULL;
        ctx->copy_end = NULL;

        ctx->pos = ctx->buf->last;

        ngx_http_replace_check_total_buffered(r, ctx, to - from,
                                              mto - mfrom);

        return NGX_AGAIN;

    case SRE_DECLINED:
        ctx->total_buffered = 0;

        return NGX_DECLINED;

    default:
        /* SRE_ERROR */
        return NGX_ERROR;
    }

    /* cannot reach here */
}


static void
ngx_http_replace_check_total_buffered(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, sre_int_t len, sre_int_t mlen)
{
    dd("total buffered: %d", (int) ctx->total_buffered);

    if ((ssize_t) ctx->total_buffered != len - mlen) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "replace filter: ctx->total_buffered out of "
                      "sync: it is %i but should be %uz",
                      ctx->total_buffered, (ngx_int_t) (len - mlen));

#if (DDEBUG)
        assert(0);
#endif
    }
}
