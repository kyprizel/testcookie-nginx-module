#ifndef _NGX_HTTP_REPLACE_FILTER_MODULE_H_INCLUDED_
#define _NGX_HTTP_REPLACE_FILTER_MODULE_H_INCLUDED_


#include "ngx_http_replace_script.h"
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <sregex/sregex.h>


extern ngx_module_t  ngx_http_replace_filter_module;


typedef struct {
    sre_int_t                  regex_id;
    sre_int_t                  stream_pos;
    sre_int_t                 *ovector;
    sre_pool_t                *vm_pool;
    sre_vm_pike_ctx_t         *vm_ctx;

    ngx_chain_t               *pending; /* pending data before the
                                           pending matched capture */
    ngx_chain_t              **last_pending;

    ngx_chain_t               *pending2; /* pending data after the pending
                                            matched capture */
    ngx_chain_t              **last_pending2;

    ngx_buf_t                 *buf;

    ngx_str_t                 *sub;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_chain_t              **last_out;
    ngx_chain_t               *busy;
    ngx_chain_t               *free;
    ngx_chain_t               *special;
    ngx_chain_t              **last_special;
    ngx_chain_t               *rematch;
    ngx_chain_t               *captured;
    ngx_chain_t              **last_captured;
    uint8_t                   *disabled;
    sre_uint_t                 disabled_count;

    size_t                     total_buffered;

    unsigned                   once:1;
    unsigned                   vm_done:1;
    unsigned                   special_buf:1;
    unsigned                   last_buf:1;
} ngx_http_replace_ctx_t;


typedef ngx_int_t (*ngx_http_replace_parse_buf_pt)(ngx_http_request_t *r,
    ngx_http_replace_ctx_t *ctx, ngx_chain_t *rematch);


typedef struct {
    sre_pool_t              *compiler_pool;
} ngx_http_replace_main_conf_t;


typedef struct {
    sre_uint_t                 ncaps;
    size_t                     ovecsize;

    ngx_array_t                multi_once;  /* of uint8_t */
    ngx_array_t                regexes;  /* of u_char* */
    ngx_array_t                multi_flags;  /* of int */
    ngx_array_t                multi_replace;
                                     /* of ngx_http_replace_complex_value_t */

    sre_program_t             *program;

    ngx_hash_t                 types;
    ngx_array_t               *types_keys;

    size_t                     max_buffered_size;

    ngx_uint_t                 last_modified;
                                    /* replace_filter_last_modified */

    ngx_http_replace_parse_buf_pt       parse_buf;
    ngx_http_replace_complex_value_t    verbatim;

    ngx_http_complex_value_t  *skip;

    unsigned                   seen_once;  /* :1 */
    unsigned                   seen_global;  /* :1 */
} ngx_http_replace_loc_conf_t;


#endif /* _NGX_HTTP_REPLACE_FILTER_MODULE_H_INCLUDED_ */
