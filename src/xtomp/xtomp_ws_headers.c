
/*
 * Contains code for processing HTTP WebSockets Upgrade headers
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_sha1.h>
#include <xtomp.h>



// Header processing
static ngx_int_t xtomp_ws_headers_host(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t xtomp_ws_headers_upgrade(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t xtomp_ws_headers_connection(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t xtomp_ws_headers_sec_websocket_key(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t xtomp_ws_headers_sec_websocket_protocol(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t xtomp_ws_headers_sec_websocket_version(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t xtomp_ws_headers_origin(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset);

/**
 * equals ignoring leading or trailing spaces
 */
static ngx_int_t
xtomp_ws_trim_equals(const u_char *match, ngx_str_t *value)
{
    u_char * v;
    ngx_uint_t len;

    len = value->len;
    if ( len == 0 ) return NGX_ERROR;

    // trim
    for  ( v = value->data ; *v == ' ' ; v++, len--);
    while ( v[len - 1] == ' ' ) len--;

    if ( len != strlen((const char *)match) ) return NGX_ERROR;

    return ngx_strncmp(match, v, len) == 0 ? NGX_OK : NGX_ERROR;

}

//SNIP_xtomp_ws_trim_contains
/**
 * Check match against a comma or space separated list
 */
static ngx_int_t
xtomp_ws_trim_contains(const u_char *match, ngx_str_t *value)
{
    u_char     *v;
    ngx_uint_t  j, k, mlen, len, matching = 0;

    len = value->len;
    if ( len == 0 ) return NGX_ERROR;

    v = value->data;

    mlen = strlen((const char *)match);
    for ( j = 0, k = 0 ; j < len ; j++, v++ ) {
       if ( *v == ' ' || *v == ',' ) {
            if ( matching && k == mlen ) return NGX_OK;
            else {
                k = 0;
                matching = 0;
                continue;
            }
        }
        if ( k > mlen ) {
            matching = 0;
            continue;
        }
        if ( match[k++] == *v) {
            matching = 1;
        }
        else {
            matching = 0;
        }
    }
    return matching && k == mlen ? NGX_OK : NGX_ERROR;
}
//SNIP_xtomp_ws_trim_contains

xtomp_header_t  xtomp_ws_headers_in[] = {
    { ngx_string("host"),                   0,  xtomp_ws_headers_host },
    { ngx_string("upgrade"),                0,  xtomp_ws_headers_upgrade },
    { ngx_string("connection"),             0,  xtomp_ws_headers_connection },
    { ngx_string("sec-websocket-key"),      0,  xtomp_ws_headers_sec_websocket_key },
    { ngx_string("sec-websocket-protocol"), 0,  xtomp_ws_headers_sec_websocket_protocol },
    { ngx_string("sec-websocket-version"),  0,  xtomp_ws_headers_sec_websocket_version },
    { ngx_string("origin"),                 0,  xtomp_ws_headers_origin },

    { ngx_null_string, 0, NULL }
};

static ngx_int_t
xtomp_ws_headers_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for ( i = 0; i < host->len; i++ ) {
        ch = h[i];

        switch (ch) {

        case '.':
            if ( dot_pos == i - 1 ) {
                return NGX_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if ( state == sw_usual ) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if ( i == 0 ) {
                state = sw_literal;
            }
            break;

        case ']':
            if ( state == sw_literal ) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return NGX_DECLINED;

        default:

            if ( ngx_path_separator(ch) ) {
                return NGX_DECLINED;
            }

            if ( ch >= 'A' && ch <= 'Z' ) {
                alloc = 1;
            }

            break;
        }
    }

    if ( dot_pos == host_len - 1 ) {
        host_len--;
    }

    if ( host_len == 0 ) {
        return NGX_DECLINED;
    }

    if ( alloc ) {
        host->data = ngx_pnalloc(pool, host_len);
        if ( host->data == NULL ) {
            return NGX_ERROR;
        }

        ngx_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NGX_OK;
}


static ngx_int_t
xtomp_ws_headers_host(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_int_t  rc;
    ngx_str_t  host;

    host = h->value;

    rc = xtomp_ws_headers_validate_host(&host, s->connection->pool, 0);

    if ( rc == NGX_DECLINED ) {
        // TODO 403
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "xtomp invalid host header");
        return NGX_ERROR;
    }

    if ( rc == NGX_ERROR ) {
        return NGX_ERROR;
    }

    s->ws->hdr_host = 1;

    return NGX_OK;
}

// All this has to be validated as per rfc6455, why not have one single header eh??

static ngx_int_t
xtomp_ws_headers_upgrade(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_strlow(h->value.data, h->value.data, h->value.len);
    ngx_int_t rc = xtomp_ws_trim_equals((u_char *)"websocket", &h->value);
    if ( rc ) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "xtomp invalid upgrade websocket header");
    }
    else s->ws->hdr_upgrade = 1;
    return rc;
}

static ngx_int_t
xtomp_ws_headers_connection(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_strlow(h->value.data, h->value.data, h->value.len);
    ngx_int_t rc = xtomp_ws_trim_contains((u_char *)"upgrade", &h->value);
    if ( rc ) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "xtomp invalid websocket connection header");
    }
    else s->ws->hdr_connection = 1;
    return rc;
}

static ngx_int_t
xtomp_ws_headers_sec_websocket_protocol(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_strlow(h->value.data, h->value.data, h->value.len);
    ngx_int_t rc = xtomp_ws_trim_equals((u_char *)"stomp", &h->value);
    if ( rc ) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "xtomp invalid websocket protocol");
    }
    else s->ws->hdr_protocol = 1;
    return rc;
}

static ngx_int_t
xtomp_ws_headers_sec_websocket_version(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_int_t rc = xtomp_ws_trim_equals((u_char *)"13", &h->value);
    if ( rc ) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "xtomp invalid websocket version");
    }
    else s->ws->hdr_version = 1;
    return rc;
}

static ngx_int_t
xtomp_ws_headers_sec_websocket_key(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset)
{
    // trim whitespace
    u_char *v;
    ngx_uint_t i = h->value.len;
    for  ( v = h->value.data ; *v == ' ' ; v++, i--);
    while ( v[i - 1] == ' ' ) i--;

    // SHA1 hash input + UUID]
    u_char hash[20];
    ngx_sha1_t ctx;
    ngx_sha1_init(&ctx);
    ngx_sha1_update(&ctx, v, i);
    ngx_sha1_update(&ctx, (u_char *)"258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
    ngx_sha1_final(hash, &ctx);

    // base64 the result & save to ws context (data needs to be freed)
    s->ws->accept = xtomp_base64(hash, 20, NULL);

    return  NGX_OK;
}

static ngx_int_t
xtomp_ws_headers_origin(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_uint_t              i;
    size_t                  olen, mlen;
    ngx_str_t               origins;
    xtomp_core_srv_conf_t  *cscf;
    u_char                 *match, *origin;

    cscf = xtomp_get_module_srv_conf(s, xtomp_core_module);

    // Extract the origin from the request
    olen = h->value.len;
    for  ( origin = h->value.data ; *origin == ' ' ; origin++, olen--);
    while ( origin[olen - 1] == ' ' ) olen--;

    ngx_strlow(origin, origin, olen);

    // Compare to allowed origins
    origins = cscf->websockets_origin;

    match = origins.data;
    mlen = 1;
    for ( i = 0 ; i < origins.len ; i++, mlen++ ) {
        if ( origins.data[i] == ',') {
            if ( mlen - 1 == olen && ngx_strncmp(match, origin, olen) == 0 ) {
                s->ws->hdr_origin = 1;
                return NGX_OK;
            }
            match = origins.data + i + 1;
            mlen = 0;
        }
        else if ( i == origins.len -1 ) {
            if ( mlen == olen && ngx_strncmp(match, origin, olen) == 0 ) {
                s->ws->hdr_origin = 1;
                return NGX_OK;
            }
        }
        
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "xtomp invalid cross origin request");
    return NGX_ERROR;
}


