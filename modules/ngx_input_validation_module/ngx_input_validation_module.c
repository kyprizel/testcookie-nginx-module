
/*
 IronFox Input Validation Module
 By: Khalgh Salehi , khaleghsalehi@gmail.com
 Copyright (c) 2016 IronFox, info@ironfox.org  * http://ironfox.org
 Thanks Xiaomi Corp for https://github.com/54chen/nginx-http-hashdos-module 
 
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef NGX_HTTP_MAX_CAPTURES
#define NGX_HTTP_MAX_CAPTURES 9
#endif

static void *ngx_http_Input_Validation_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_Input_Validation_merge_loc_conf(ngx_conf_t *cf,
                                                      void *parent,
                                                      void *child);

static ngx_int_t ngx_http_Input_Validation_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_Input_Validation_handler(ngx_http_request_t *r);

static void ngx_Input_Validation_request_body_handler(ngx_http_request_t *r);

static char *ngx_http_Check_Input_Validation(ngx_conf_t *cf,
                                             ngx_command_t *cmd,
                                             void *conf);

int string_ln(char *p);


int string_ln(char *p) {
    int count = 0;
    while (*p != '\0') {
        count++;
        p++;
    }
    return count;
}

typedef struct {
    /* Nginx config format:     Value Type Length Action;
     * e.g 						username "^[A-Za-z0-9]" 15 block;
     *							Discription:
     *							if the username do not match with [A-Za-z0-9] and the len > 15 then drop request
    */
    ngx_str_t body_args_name; // Name of Variable
    ngx_str_t body_args_type; // Type of Variable
    ngx_str_t body_args_len; // Length of Variable
    ngx_str_t action; // Action [Block/Learn]
    int *captures;
    ngx_int_t ncaptures;
    ngx_regex_t *match_regex;
} Input_Validation_Args;

/*
 * Module configuration struct
 */
typedef struct {
    ngx_flag_t enable;
    ngx_int_t body_max_count;
    ngx_array_t *Input_Validation_Items; // array of Input_Validation_Args
} ngx_http_Input_Validation_loc_conf_t;

typedef struct {
    ngx_flag_t done:1;
    ngx_flag_t waiting_more_body:1;
} ngx_http_post_read_ctx_t;

/*
Module directive
struct ngx_command_t {
    ngx_str_t             name;
    ngx_uint_t            type;
    char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
    ngx_uint_t            conf;
    ngx_uint_t            offset;
    void                 *post;
};
 */

static ngx_command_t ngx_http_Input_Validation_commands[] = {
        {ngx_string("input_validation"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_Input_Validation_loc_conf_t, enable),
         NULL},

        {ngx_string("input_validation_arg"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE4,
         ngx_http_Check_Input_Validation,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        {ngx_string("input_validation_max_arg"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_num_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_Input_Validation_loc_conf_t, body_max_count),
         NULL},
        ngx_null_command
};


static ngx_http_module_t ngx_http_Input_Validation_module_ctx = {
        NULL,                                  /* preconfiguration */
        ngx_http_Input_Validation_init,        /* postconfiguration */

        NULL,                                  /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        ngx_http_Input_Validation_create_loc_conf,       /* create location configuration */
        ngx_http_Input_Validation_merge_loc_conf         /* merge location configuration */
};

static void *ngx_http_Input_Validation_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_Input_Validation_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_Input_Validation_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->body_max_count = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_Input_Validation_merge_loc_conf(ngx_conf_t *cf,
                                                      void *parent,
                                                      void *child) {
    ngx_http_Input_Validation_loc_conf_t *prev = parent;
    ngx_http_Input_Validation_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable,
                         prev->enable,
                         1);
    ngx_conf_merge_value(conf->body_max_count,
                         prev->body_max_count,
                         1000);
    return NGX_CONF_OK;
}

/*
 *  Module definition
 */
ngx_module_t ngx_http_Input_Validation_module = {
        NGX_MODULE_V1,
        &ngx_http_Input_Validation_module_ctx,                /* module context */
        ngx_http_Input_Validation_commands,                /* module directives */
        NGX_HTTP_MODULE,                                    /* module type */
        NULL,                                            /* init master */
        NULL,                                                /* init module */
        NULL,                                                /* init process */
        NULL,                                                /* init thread */
        NULL,                                            /* exit thread */
        NULL,                                            /* exit process */
        NULL,                                                /* exit master */
        NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_Input_Validation_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_Input_Validation_handler;
    return NGX_OK;
}

static ngx_int_t ngx_http_Input_Validation_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Input_Validation] Start Input Validator.");
    ngx_int_t rc;
    ngx_http_Input_Validation_loc_conf_t *alcf;
    ngx_http_post_read_ctx_t *ctx;

    alcf = ngx_http_get_module_loc_conf(r,
                                        ngx_http_Input_Validation_module);
    if (!alcf->enable) {
        return NGX_OK;
    }
    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_Input_Validation_module);
    if (ctx != NULL) {
        if (ctx->done) {
            return NGX_DECLINED;
        }
        return NGX_DONE;
    }
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_post_read_ctx_t));

    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_Input_Validation_module);

    rc = ngx_http_read_client_request_body(r,
                                           ngx_Input_Validation_request_body_handler);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Input_Validation] Body Request is -> [%O] ", rc);
        return rc;
    }

    if (rc == NGX_AGAIN) {
        ctx->waiting_more_body = 1;
        return NGX_DONE;
    }

    return NGX_DECLINED;
}


static char *ngx_http_Check_Input_Validation(ngx_conf_t *cf,
                                             ngx_command_t *cmd,
                                             void *conf) {
    ngx_http_Input_Validation_loc_conf_t *rlcf = conf;
    ngx_str_t *value;
    Input_Validation_Args *pair;
    // dont forget for any error handeling here, e.g NULL, etc...
    value = cf->args->elts;

    if (rlcf->Input_Validation_Items == NULL) {
        rlcf->Input_Validation_Items = ngx_array_create(cf->pool,
                                                        4,
                                                        sizeof(Input_Validation_Args));
        if (rlcf->Input_Validation_Items == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    pair = ngx_array_push(rlcf->Input_Validation_Items);
    if (pair == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(pair, sizeof(Input_Validation_Args));
    pair->body_args_name = value[1];
    pair->body_args_type = value[2];
    pair->body_args_len = value[3];
    pair->action = value[4];
    return NGX_CONF_OK;
}


static void ngx_Input_Validation_request_body_handler(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Input_Validation] Body Transferring is over.");
    ngx_http_Input_Validation_loc_conf_t *alcf;
    ngx_int_t count, limit;
    u_char ch, *p;
    ngx_chain_t *cl;
    ngx_buf_t *buf, *next;
    ngx_http_post_read_ctx_t *ctx;
    ngx_uint_t i;
    ngx_int_t check_len = 0;
    Input_Validation_Args *pairp, *pair;

    //Regex
    ngx_int_t matchstatus = 0;
    ngx_regex_compile_t rc;
    ngx_str_t err;
    ngx_int_t options;
    options = 0;

    r->read_event_handler = ngx_http_request_empty_handler;
    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_Input_Validation_module);
    ctx->done = 1;
    r->main->count--;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Input_Validation] Body Buffer is empty {NULL}");
        return;
    }

    alcf = ngx_http_get_module_loc_conf(r,
                                        ngx_http_Input_Validation_module);
    if (alcf->body_max_count <= 0) {
        limit = 800; //Change with your own risk, more value maybe cause DoS attack
    } else {
        limit = alcf->body_max_count;
    }

    count = 0;

    cl = r->request_body->bufs;
    buf = cl->buf;
    next = '\0';

    if (cl->next == NULL) {


/*
 *
 * Input Validation
 */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[InputValidation] **** Start Input Validation ****");
        pairp = (Input_Validation_Args *) alcf->Input_Validation_Items->elts;
        for (i = 0; i < alcf->Input_Validation_Items->nelts; i++) {
            pair = &pairp[i];
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "[Input_Validation] ========================================");
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Input_Validation] Arg[Name]:  %s",
                           pair->body_args_name.data);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Input_Validation] Arg[Type]:  %s",
                           pair->body_args_type.data);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Input_Validation] Arg[Len]:  %s",
                           pair->body_args_len.data);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "[Input_Validation] ========================================");
            char BUFF[1024];
            int ic = 0;
            for (p = buf->pos; p < buf->last; p++) {
                //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[InputValidation]  value %c",*p);
                // Store characters in BUFF
                BUFF[ic] = *p;
                ic++;
            }
            BUFF[1024] = '\0'; // Null char for end of buffer
            char *pch;
            pch = strtok(BUFF, "&");
            while (pch != NULL) {
                if (ngx_strstr(pch, pair->body_args_name.data)) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Input_Validation] Item found.%s", pch);
                    /*First store the pch in another buffer and then delimit the sub-string*/
                    char *pch2;
                    char BUFF2[1024];
                    BUFF2[1024] = '\0';
                    strncpy(BUFF2, pch, 1023);
                    int count = 1;
                    pch2 = strtok(BUFF2, "=");
                    while (pch2 != NULL) {
                        if (count > 1) {
                            // Variable=Value , we going to inspect the Value's Type & Length
                            // #Step 1, check the length
                            check_len = ngx_atoi(pair->body_args_len.data,
                                                 ngx_strlen(pair->body_args_len.data));
                            if (check_len >= string_ln(pch2)) {
                                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                               "[Input_Validation] Item Value %s", pch2);
                                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                               "[Input_Validation] Item Size %d", check_len);
                            }
                            if (check_len < string_ln(pch2)) {
                                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                               "[Input_Validation] Buffer Overflow Attack , Value %d", check_len);
                                // depend on the pair->action status ( block mode or profilng)
                                //return NGX_ERROR;
                            }
                            // #Step 2, check the type, using ngx_regex
                            rc.pattern = pair->body_args_type;
                            rc.pool = r->pool;
                            rc.err = err;
                            rc.options = options;
                            if (ngx_regex_compile(&rc) == NGX_OK) {
                                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                               "[Input_Validation] Regex Ok");
                            }
                            if (ngx_regex_compile(&rc) != NGX_OK) {
                                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                               "[Input_Validation] Regex Error");
                            }


                            if (pair->captures == NULL || pair->ncaptures == 0) {
                                pair->ncaptures = (NGX_HTTP_MAX_CAPTURES + 1) * 3;
                                pair->captures = ngx_palloc(r->pool,
                                                            pair->ncaptures * sizeof(int));
                                if (pair->captures == NULL) {
                                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                                   "[Input_Validation] cpatures allocation error");
                                }
                            }


                            char ASL[1024];
                            memset(ASL, '\0', 1024);
                            strncpy(ASL, pch2, 1024);
                            ngx_str_t dd_str = ngx_string(ASL);
                            pair->match_regex = rc.regex;
                            matchstatus = ngx_regex_exec(pair->match_regex,
                                                         &dd_str,
                                                         (int *) pair->captures,
                                                         pair->ncaptures);
                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                           "[Input_Validation] ASL ->  , Value [%s]", dd_str.data);

                            if (matchstatus == NGX_REGEX_NO_MATCHED) {
                                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                               "[Input_Validation] ==[ Type Attack ]==");
                                if (ngx_strstr(pair->action.data, "block")) {
                                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                                   "[Input_Validation] Blocking Mod");
                                    // if Block Mod then send error and reject request
                                    ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
                                }
                                if (ngx_strstr(pair->action.data, "learn")) {
                                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                                   "[Input_Validation] Profiling Mod");
                                }
                            }
                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                           "[Input_Validation] matchstatus , Value %d", matchstatus);

                            if (matchstatus != NGX_REGEX_NO_MATCHED) {
                                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                               "[Input_Validation] ==[ Type Match, Safe.]==");

                            }
                        }
                        pch2 = strtok(NULL, "=");
                        count++;
                    }// End of While
                }// End of if
                pch = strtok(NULL, "&");
            }// End of While...
        }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[Input_Validation] **** End of Input Validation ****");

/*
 *
 * Input Validation
 */

        for (p = buf->pos; p < buf->last; p++) {
            ch = *p;

            if (ch == '&') {
                count++;
            }
        }
    }
    if (cl->next != NULL) {
        for (; cl; cl = cl->next) {
            next = cl->buf;

            if (next->in_file) {
                ngx_log_error(NGX_LOG_ERR,
                              r->connection->log,
                              0, "[Input_Validation] in-file buffer found. aborted."
                                 " consider increasing your client_body_buffer_size setting.");
                ctx->waiting_more_body = 0;
                ctx->done = 1;
                r->main->count--;
                return;
            }

            for (p = next->pos; p < next->last; p++) {
                ch = *p;
                if (ch == '&') {
                    count++;
                }
            }
        }
    }
    ++count;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[Input_Validation] parse request body parameters count is [%O], limit is [%O]", count, limit);
    if (count >= limit) {
        (void) ngx_http_discard_request_body(r);
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        ngx_log_error(NGX_LOG_ERR,
                      r->connection->log,
                      0,
                      "[Input_Validation] in rb->bfs -> client intended to send too large body: %O bytes, body size: %O, limit is: %O",
                      r->headers_in.content_length_n,
                      count,
                      limit);
        ctx->waiting_more_body = 0;
        ctx->done = 1;
        r->main->count--;
    }

    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}


