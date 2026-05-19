#ifndef _NGX_HTTP_REPLACE_UTIL_H_INCLUDED_
#define _NGX_HTTP_REPLACE_UTIL_H_INCLUDED_


#include "ngx_http_replace_filter_module.h"


ngx_chain_t *ngx_http_replace_get_free_buf(ngx_pool_t *p,
    ngx_chain_t **free);
ngx_int_t ngx_http_replace_split_chain(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, ngx_chain_t **pa, ngx_chain_t ***plast_a,
    sre_int_t split, ngx_chain_t **pb, ngx_chain_t ***plast_b, unsigned b_sane);
ngx_int_t ngx_http_replace_new_pending_buf(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, sre_int_t from, sre_int_t to,
    ngx_chain_t **out);
#if (DDEBUG)
void ngx_http_replace_dump_chain(const char *prefix, ngx_chain_t **pcl,
    ngx_chain_t **last);
#endif


#endif /* _NGX_HTTP_REPLACE_UTIL_H_INCLUDED_ */
