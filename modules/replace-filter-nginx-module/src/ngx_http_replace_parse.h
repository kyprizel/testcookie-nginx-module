#ifndef _NGX_HTTP_REPLACE_PARSE_H_INCLUDED_
#define _NGX_HTTP_REPLACE_PARSE_H_INCLUDED_


#include "ngx_http_replace_filter_module.h"


ngx_int_t ngx_http_replace_non_capturing_parse(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, ngx_chain_t *rematch);
ngx_int_t ngx_http_replace_capturing_parse(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, ngx_chain_t *rematch);


#endif /* _NGX_HTTP_REPLACE_PARSE_H_INCLUDED_ */
