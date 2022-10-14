
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_replace_script.h"


static void *ngx_http_replace_script_add_code(ngx_array_t *codes, size_t size);
static size_t ngx_http_replace_script_copy_len_code(
    ngx_http_replace_script_engine_t *e);
static size_t
    ngx_http_replace_script_copy_code(ngx_http_replace_script_engine_t *e);
static ngx_int_t ngx_http_replace_script_add_copy_code(
    ngx_http_replace_script_compile_t *sc, ngx_str_t *value, ngx_uint_t last);
static ngx_int_t
    ngx_http_replace_script_compile(ngx_http_replace_script_compile_t *sc);
static ngx_int_t ngx_http_replace_script_add_capture_code(
    ngx_http_replace_script_compile_t *sc, ngx_uint_t n);
static size_t ngx_http_replace_script_copy_capture_len_code(
    ngx_http_replace_script_engine_t *e);
static size_t ngx_http_replace_script_copy_capture_code(
    ngx_http_replace_script_engine_t *e);
static ngx_int_t
    ngx_http_replace_script_done(ngx_http_replace_script_compile_t *sc);
static ngx_int_t ngx_http_replace_script_init_arrays(
    ngx_http_replace_script_compile_t *sc);
static ngx_int_t
    ngx_http_replace_script_add_var_code(ngx_http_replace_script_compile_t *sc,
    ngx_str_t *name);
static size_t
    ngx_http_replace_script_copy_var_len_code(
    ngx_http_replace_script_engine_t *e);
static size_t
    ngx_http_replace_script_copy_var_code(ngx_http_replace_script_engine_t *e);
static void ngx_http_replace_count_variables(u_char *src, size_t len,
    ngx_uint_t *ngxvars, ngx_uint_t *capvars);


ngx_int_t
ngx_http_replace_compile_complex_value(
    ngx_http_replace_compile_complex_value_t *ccv)
{
    ngx_str_t                  *v;
    ngx_uint_t                  n, ngxvars, capvars;
    ngx_array_t                 lengths, values, *pl, *pv;

    ngx_http_replace_script_compile_t   sc;

    v = ccv->value;

    ngx_http_replace_count_variables(v->data, v->len, &ngxvars, &capvars);

    ccv->complex_value->value = *v;
    ccv->complex_value->lengths = NULL;
    ccv->complex_value->values = NULL;

    if (capvars == 0 && ngxvars == 0) {
        return NGX_OK;
    }

    n = capvars * (2 * sizeof(ngx_http_replace_script_copy_code_t)
                   + sizeof(ngx_http_replace_script_capture_code_t))
        + ngxvars * (2 * sizeof(ngx_http_replace_script_copy_code_t)
                     + sizeof(ngx_http_replace_script_var_code_t))
        + sizeof(uintptr_t);

    if (ngx_array_init(&lengths, ccv->cf->pool, n, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    n = capvars * (2 * sizeof(ngx_http_replace_script_copy_code_t)
                   + sizeof(ngx_http_replace_script_capture_code_t))
        + ngxvars * (2 * sizeof(ngx_http_replace_script_var_code_t)
                     + sizeof(ngx_http_replace_script_var_code_t))
        + sizeof(uintptr_t);

    if (ngx_array_init(&values, ccv->cf->pool, n, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    pl = &lengths;
    pv = &values;

    ngx_memzero(&sc, sizeof(ngx_http_replace_script_compile_t));

    sc.cf = ccv->cf;
    sc.source = v;
    sc.lengths = &pl;
    sc.values = &pv;

    if (ngx_http_replace_script_compile(&sc) != NGX_OK) {
        ngx_array_destroy(&lengths);
        ngx_array_destroy(&values);
        return NGX_ERROR;
    }

    ccv->complex_value->lengths = lengths.elts;
    ccv->complex_value->values = values.elts;
    ccv->complex_value->capture_variables = sc.capture_variables;

    return NGX_OK;
}


ngx_int_t
ngx_http_replace_complex_value(ngx_http_request_t *r,
    ngx_chain_t *captured, sre_uint_t ncaps, sre_int_t *cap,
    ngx_http_replace_complex_value_t *val, ngx_str_t *value)
{
    size_t                                len;
    ngx_http_replace_script_code_pt       code;
    ngx_http_replace_script_len_code_pt   lcode;
    ngx_http_replace_script_engine_t      e;

    if (val->lengths == NULL) {
        *value = val->value;
        return NGX_OK;
    }

    ngx_memzero(&e, sizeof(ngx_http_replace_script_engine_t));

    e.request = r;
    e.ncaptures = (ncaps + 1) * 2;
    e.captures_data = captured;
    e.captures = cap;
    e.ip = val->lengths;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(ngx_http_replace_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = ngx_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return NGX_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(ngx_http_replace_script_code_pt *) e.ip;
        code((ngx_http_replace_script_engine_t *) &e);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_replace_script_compile(ngx_http_replace_script_compile_t *sc)
{
    u_char       ch;
    ngx_str_t    name;
    ngx_uint_t   i, bracket;
    unsigned     num_var;
    ngx_uint_t   n = 0;

    if (ngx_http_replace_script_init_arrays(sc) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < sc->source->len; /* void */ ) {

        name.len = 0;

        if (sc->source->data[i] == '$') {

            if (++i == sc->source->len) {
                goto invalid_variable;
            }

            if (sc->source->data[i] == '$') {
                name.data = &sc->source->data[i];
                i++;
                name.len++;
                sc->size += name.len;

                if (ngx_http_replace_script_add_copy_code(sc, &name,
                                                      (i == sc->source->len))
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if ((sc->source->data[i] >= '1' && sc->source->data[i] <= '9')
                || sc->source->data[i] == '&')
            {
                num_var = 1;
                n = 0;

            } else {
                num_var = 0;
            }

            if (sc->source->data[i] == '{') {
                bracket = 1;

                if (++i == sc->source->len) {
                    goto invalid_variable;
                }

                if ((sc->source->data[i] >= '1' && sc->source->data[i] <= '9')
                    || sc->source->data[i] == '&')
                {
                    num_var = 1;
                    n = 0;
                }

                name.data = &sc->source->data[i];

            } else {
                bracket = 0;
                name.data = &sc->source->data[i];
            }

            for ( /* void */ ; i < sc->source->len; i++, name.len++) {
                ch = sc->source->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if (num_var) {
                    if (ch >= '0' && ch <= '9') {
                        n = n * 10 + (ch - '0');
                        continue;
                    }

                    if (ch == '&') {
                        i++;
                        name.len++;
                    }

                    break;
                }

                /* not a number variable like $1, $2, etc */

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                ngx_log_error(NGX_LOG_ERR, sc->cf->log, 0,
                              "the closing bracket in \"%V\" "
                              "variable is missing", &name);
                return NGX_ERROR;
            }

            if (name.len == 0) {
                goto invalid_variable;
            }

            if (num_var) {
                dd("found numbered capturing variable \"%.*s\"",
                   (int) name.len, name.data);

                sc->capture_variables++;

                if (ngx_http_replace_script_add_capture_code(sc, n) != NGX_OK) {
                    return NGX_ERROR;
                }

            } else {
                sc->nginx_variables++;

                if (ngx_http_replace_script_add_var_code(sc, &name) != NGX_OK) {
                    return NGX_ERROR;
                }
            }

            continue;
        }

        name.data = &sc->source->data[i];

        while (i < sc->source->len) {

            if (sc->source->data[i] == '$') {
                break;
            }

            i++;
            name.len++;
        }

        sc->size += name.len;

        if (ngx_http_replace_script_add_copy_code(sc, &name,
                                                  (i == sc->source->len))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return ngx_http_replace_script_done(sc);

invalid_variable:

    ngx_log_error(NGX_LOG_ERR, sc->cf->log, 0,
                  "replace script: invalid capturing variable name found "
                  "in \"%V\"", sc->source);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_replace_script_add_copy_code(ngx_http_replace_script_compile_t *sc,
    ngx_str_t *value, ngx_uint_t last)
{
    size_t                                size, len;
    ngx_http_replace_script_copy_code_t  *code;

    len = value->len;

    code = ngx_http_replace_script_add_code(*sc->lengths,
                                 sizeof(ngx_http_replace_script_copy_code_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_http_replace_script_code_pt)
                 ngx_http_replace_script_copy_len_code;
    code->len = len;

    size = (sizeof(ngx_http_replace_script_copy_code_t) + len +
            sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);

    code = ngx_http_replace_script_add_code(*sc->values, size);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_http_replace_script_code_pt)
                 ngx_http_replace_script_copy_code;
    code->len = len;

    ngx_memcpy((u_char *) code + sizeof(ngx_http_replace_script_copy_code_t),
               value->data, value->len);

    return NGX_OK;
}


static size_t
ngx_http_replace_script_copy_len_code(ngx_http_replace_script_engine_t *e)
{
    ngx_http_replace_script_copy_code_t  *code;

    code = (ngx_http_replace_script_copy_code_t *) e->ip;

    e->ip += sizeof(ngx_http_replace_script_copy_code_t);

    return code->len;
}


static size_t
ngx_http_replace_script_copy_code(ngx_http_replace_script_engine_t *e)
{
    u_char      *p;

    ngx_http_replace_script_copy_code_t  *code;

    code = (ngx_http_replace_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = ngx_copy(p, e->ip
                          + sizeof(ngx_http_replace_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(ngx_http_replace_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "replace script copy: \"%*s\"", e->pos - p, p);

    return 0;
}


static ngx_int_t
ngx_http_replace_script_add_capture_code(ngx_http_replace_script_compile_t *sc,
    ngx_uint_t n)
{
    ngx_http_replace_script_capture_code_t  *code;

    code = ngx_http_replace_script_add_code(*sc->lengths,
                         sizeof(ngx_http_replace_script_capture_code_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_http_replace_script_code_pt)
                 ngx_http_replace_script_copy_capture_len_code;
    code->n = 2 * n;

    code = ngx_http_replace_script_add_code(*sc->values,
                         sizeof(ngx_http_replace_script_capture_code_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_http_replace_script_code_pt)
                 ngx_http_replace_script_copy_capture_code;
    code->n = 2 * n;

    return NGX_OK;
}


static size_t
ngx_http_replace_script_copy_capture_len_code(
    ngx_http_replace_script_engine_t *e)
{
    sre_int_t                            *cap;
    ngx_uint_t                            n;

    ngx_http_replace_script_capture_code_t  *code;

    code = (ngx_http_replace_script_capture_code_t *) e->ip;

    e->ip += sizeof(ngx_http_replace_script_capture_code_t);

    n = code->n;

    dd("group index: %d, ncaptures: %d", (int) n, (int) e->ncaptures);

    if (n + 1 < e->ncaptures) {
        cap = e->captures;
        return cap[n + 1] - cap[n];
    }

    return 0;
}


static size_t
ngx_http_replace_script_copy_capture_code(ngx_http_replace_script_engine_t *e)
{
    sre_int_t                            *cap, from, to, len;
    u_char                               *p;
#if (NGX_DEBUG)
    u_char                               *pos;
#endif
    ngx_uint_t                            n;
    ngx_chain_t                          *cl;

    ngx_http_replace_script_capture_code_t  *code;

    code = (ngx_http_replace_script_capture_code_t *) e->ip;

    e->ip += sizeof(ngx_http_replace_script_capture_code_t);

    n = code->n;

#if (NGX_DEBUG)
    pos = e->pos;
#endif

    if (n < e->ncaptures) {

        cap = e->captures;
        from = cap[n];
        to = cap[n + 1];

        dd("captures data: %p", e->captures_data);

        for (cl = e->captures_data; cl; cl = cl->next) {

            if (from >= cl->buf->file_last) {
                continue;
            }

            /* from < cl->buf->file_last */

            if (to <= cl->buf->file_pos) {
                break;
            }

            p = cl->buf->pos + (from - cl->buf->file_pos);
            len = ngx_min(cl->buf->file_last, to) - from;
            e->pos = ngx_copy(e->pos, p, len);
            from += len;
        }
    }

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "replace script capture: \"%*s\"", e->pos - pos, pos);
#endif

    return 0;
}


static ngx_int_t
ngx_http_replace_script_init_arrays(ngx_http_replace_script_compile_t *sc)
{
    ngx_uint_t   n;

    if (*sc->lengths == NULL) {
        n = sc->capture_variables
            * (2 * sizeof(ngx_http_replace_script_copy_code_t)
               + sizeof(ngx_http_replace_script_capture_code_t))
            + sc->nginx_variables
            * (2 * sizeof(ngx_http_replace_script_copy_code_t)
               + sizeof(ngx_http_replace_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = ngx_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return NGX_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = sc->capture_variables
            * (2 * sizeof(ngx_http_replace_script_copy_code_t)
               + sizeof(ngx_http_replace_script_capture_code_t))
            + sc->nginx_variables
              * (2 * sizeof(ngx_http_replace_script_copy_code_t)
                 + sizeof(ngx_http_replace_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->values = ngx_array_create(sc->cf->pool, n, 1);
        if (*sc->values == NULL) {
            return NGX_ERROR;
        }
    }

    sc->nginx_variables = 0;
    sc->capture_variables = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_replace_script_done(ngx_http_replace_script_compile_t *sc)
{
    uintptr_t   *code;

    code = ngx_http_replace_script_add_code(*sc->lengths,
                                            sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;

    code = ngx_http_replace_script_add_code(*sc->values, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;

    return NGX_OK;
}


static void *
ngx_http_replace_script_add_code(ngx_array_t *codes, size_t size)
{
    return ngx_array_push_n(codes, size);
}


static ngx_int_t
ngx_http_replace_script_add_var_code(ngx_http_replace_script_compile_t *sc,
    ngx_str_t *name)
{
    ngx_int_t                            index;
    ngx_http_replace_script_var_code_t  *code;

    index = ngx_http_get_variable_index(sc->cf, name);

    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    code = ngx_http_replace_script_add_code(*sc->lengths,
                                  sizeof(ngx_http_replace_script_var_code_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_http_replace_script_code_pt)
                 ngx_http_replace_script_copy_var_len_code;

    code->index = (uintptr_t) index;

    code = ngx_http_replace_script_add_code(*sc->values,
                                  sizeof(ngx_http_replace_script_var_code_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_http_replace_script_code_pt)
                 ngx_http_replace_script_copy_var_code;
    code->index = (uintptr_t) index;

    return NGX_OK;
}


static size_t
ngx_http_replace_script_copy_var_len_code(ngx_http_replace_script_engine_t *e)
{
    ngx_http_variable_value_t           *value;
    ngx_http_replace_script_var_code_t  *code;

    code = (ngx_http_replace_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_http_replace_script_var_code_t);

    value = ngx_http_get_indexed_variable(e->request, code->index);

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


static size_t
ngx_http_replace_script_copy_var_code(ngx_http_replace_script_engine_t *e)
{
    u_char                              *p;
    ngx_http_variable_value_t           *value;
    ngx_http_replace_script_var_code_t  *code;

    code = (ngx_http_replace_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_http_replace_script_var_code_t);

    if (!e->skip) {

        value = ngx_http_get_indexed_variable(e->request, code->index);

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = ngx_copy(p, value->data, value->len);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP,
                           e->request->connection->log, 0,
                           "http replace script var: \"%*s\"", e->pos - p, p);
        }
    }

    return 0;
}


static void
ngx_http_replace_count_variables(u_char *src, size_t len,
    ngx_uint_t *ngxvars, ngx_uint_t *capvars)
{
    ngx_uint_t          i;
    unsigned            var = 0;
    u_char              c;

    *ngxvars = 0;
    *capvars = 0;

    for (i = 0; i < len; i++) {
        c = src[i];

        if (c == '$') {
            if (var) {
                var = 0;

            } else {
                var = 1;
            }

        } else if (var) {
            if ((c >= '1' && c <= '9') || c == '&') {
                (*capvars)++;

            } else {
                (*ngxvars)++;
            }

            var = 0;
        }
    }
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
