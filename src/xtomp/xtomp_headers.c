
/*
 * Contains code for processing STOMP message headers
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



// Header processing
static ngx_int_t xtomp_headers_host(xtomp_session_t *sess, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t xtomp_headers_login(xtomp_session_t *sess, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t xtomp_headers_line(xtomp_session_t *sess, ngx_table_elt_t *h, ngx_uint_t offset);

xtomp_header_t  xtomp_headers_in[] = {
    { ngx_string("host"),           offsetof(xtomp_headers_in_t, host),           xtomp_headers_host },
    { ngx_string("destination"),    offsetof(xtomp_headers_in_t, destination),    xtomp_headers_line },
    { ngx_string("content-length"), offsetof(xtomp_headers_in_t, content_length), xtomp_headers_line },
    { ngx_string("login"),          offsetof(xtomp_headers_in_t, login),          xtomp_headers_login },
    { ngx_string("passcode"),       offsetof(xtomp_headers_in_t, passcode),       xtomp_headers_line },
    { ngx_string("receipt"),        offsetof(xtomp_headers_in_t, receipt),        xtomp_headers_line },
    { ngx_string("heart-beat"),     offsetof(xtomp_headers_in_t, heart_beat),     xtomp_headers_line },
    { ngx_string("message-id"),     offsetof(xtomp_headers_in_t, id),             xtomp_headers_line },
    // STOMP 1.2 changed the name
    { ngx_string("id"),             offsetof(xtomp_headers_in_t, id),             xtomp_headers_line },

    { ngx_null_string, 0, NULL }
};



ngx_int_t
xtomp_headers_unset(xtomp_session_t *sess)
{
    ngx_int_t   i;
    ngx_table_elt_t  **ph;

    // pcalloc in xtomp_request_header_done()
    if ( sess->headers_in.host ) {
        xtomp_free(sess->headers_in.host->key.data);
        xtomp_free(sess->headers_in.host);
    }
    if ( sess->headers_in.destination ) {
        xtomp_free(sess->headers_in.destination->key.data);
        xtomp_free(sess->headers_in.destination);
    }
    if ( sess->headers_in.ack ) {
        xtomp_free(sess->headers_in.ack->key.data);
        xtomp_free(sess->headers_in.ack);
    }
    if ( sess->headers_in.content_length ) {
        xtomp_free(sess->headers_in.content_length->key.data);
        xtomp_free(sess->headers_in.content_length);
    }
    if ( sess->headers_in.login ) {
        xtomp_free(sess->headers_in.login->key.data);
        xtomp_free(sess->headers_in.login);
    }
    if ( sess->headers_in.passcode ) {
        xtomp_free(sess->headers_in.passcode->key.data);
        xtomp_free(sess->headers_in.passcode);
    }
    if ( sess->headers_in.receipt ) {
        xtomp_free(sess->headers_in.receipt->key.data);
        xtomp_free(sess->headers_in.receipt);
    }
    if ( sess->headers_in.heart_beat ) {
        xtomp_free(sess->headers_in.heart_beat->key.data);
        xtomp_free(sess->headers_in.heart_beat);
    }
    if ( sess->headers_in.id ) {
        xtomp_free(sess->headers_in.id->key.data);
        xtomp_free(sess->headers_in.id);
    }

    ph = sess->headers_in.user_def;
    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        if ( ph[i] != NULL ) {
            xtomp_free(ph[i]->key.data);
            xtomp_free(ph[i]);
        }
    }

    ngx_memset(&sess->headers_in,  0, sizeof(xtomp_headers_in_t));

    return NGX_OK;
}

/*
 * Copy to newly malloced space
 */
ngx_int_t
xtomp_headers_cpy(ngx_table_elt_t *h_in, ngx_table_elt_t **h_new)
{

    u_char             *p, *start;
    ngx_table_elt_t    *h_work;

    if ( h_new ) {
        h_work = xtomp_calloc(1, sizeof(ngx_table_elt_t));
        if ( h_work == NULL ) {
            return NGX_ERROR;
        }
    } 
    else {
        h_work = h_in;
    }

    p = xtomp_calloc(1, h_in->key.len + h_in->value.len + 2);
    if ( p == NULL ) {
        if ( h_new ) xtomp_free(h_work);
        return NGX_ERROR;
    }

    start = p;
    ngx_memcpy(p, h_in->key.data, h_in->key.len);
    p += h_in->key.len;
    *p++ = ':';
    ngx_memcpy(p, h_in->value.data, h_in->value.len);
    p += h_in->value.len;
    *p = 0;

    h_work->key.data = start;
    h_work->key.len = h_in->key.len;
    h_work->value.data = start + h_in->key.len + 1;
    h_work->value.len = h_in->value.len;

    if ( h_new ) *h_new = h_work;

    return NGX_OK;
}

ngx_int_t
xtomp_headers_user_def_add(xtomp_session_t *sess, ngx_table_elt_t *h) {
    ngx_int_t           i, rc;
    ngx_table_elt_t   **ph;

    ph = sess->headers_in.user_def;

    if ( h->key.len + h->value.len + 1 > XTOMP_MAX_HDR_LEN ) {
        xtomp_free(h);
        return XTOMP_HDR_FLUP;
    }

    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        if ( ph[i] == NULL ) {

            // memcpy data from buffer, hds live longer than sess->buffer
            ph[i] = h;
            rc = xtomp_headers_cpy(h, NULL); 
            if ( rc != NGX_OK ) {
                xtomp_free(h);
                return NGX_ERROR;
            }
            return NGX_OK;
        }
    }

    xtomp_free(h);
    return XTOMP_HDR_FLUP;
}



ngx_str_t*
xtomp_headers_user_def_find(xtomp_session_t *sess, ngx_str_t *name) {
    ngx_int_t           i;
    ngx_table_elt_t   **ph;

    ph = sess->headers_in.user_def;

    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        if ( ph[i] != NULL ) {
            if (xtomp_strcmp(name, &ph[i]->key) == 0 ) {
                return &ph[i]->value;
            }
        }
    }

    return NULL;
}



/*
 * print name:value\n for each header
 */
ngx_int_t
xtomp_headers_user_def_print(u_char *bufout, ngx_table_elt_t *hdrs[]) {
    ngx_int_t   i;

    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        if ( hdrs[i] ) {
            ngx_memcpy(bufout, hdrs[i]->key.data, hdrs[i]->key.len + 1 + hdrs[i]->value.len);
            bufout += hdrs[i]->key.len + 1 + hdrs[i]->value.len;
            *bufout++ = '\n';
        }
    }

    return NGX_OK;
}

/*
 * returns length for name:value\n for each header
 */
ngx_int_t
xtomp_headers_len(ngx_table_elt_t *hdrs[]) {
    ngx_int_t   i, len;

    for ( i = 0, len = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        if ( hdrs[i] ) {
            len += hdrs[i]->key.len + 1 + hdrs[i]->value.len + 1;
        }
    }

    return len;
}



/*
 * move user_def headers from session to message being uploaded
 */
ngx_int_t
xtomp_headers_move(xtomp_message_t *m, xtomp_session_t *sess) {
    ngx_int_t           i;
    ngx_table_elt_t   **hds_in;

    hds_in = sess->headers_in.user_def;

    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        if ( hds_in[i] ) {
            m->hdrs[i] = hds_in[i];
            hds_in[i] = NULL;
        }
    }

    return NGX_OK;
}

// TODO sniptest below



/**
 * @param offset is a byte offset, pointers math must use word size
 * C can do this with casts but not on ARM
 */
static ngx_int_t
xtomp_headers_line(xtomp_session_t *sess, ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_table_elt_t  **h_ptr;

    h_ptr = &sess->headers_in.host;
    h_ptr += (offset / sizeof(ngx_table_elt_t *));
    if ( *h_ptr == NULL ) {
        *h_ptr = h;
        xtomp_headers_cpy(h, NULL);
    }
    else {
        // ignore duplicates
        xtomp_free(h);
    }

    return NGX_OK;
}



static ngx_int_t
xtomp_headers_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
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
xtomp_headers_host(xtomp_session_t *sess, ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_int_t  rc;
    ngx_str_t  host;

    if ( sess->headers_in.host == NULL ) {
        sess->headers_in.host = h;
        xtomp_headers_cpy(h, NULL);
    }
    else {
        xtomp_free(h);
        return NGX_OK;
    }

    host = h->value;

    rc = xtomp_headers_validate_host(&host, sess->connection->pool, 0);

    if ( rc == NGX_DECLINED ) {
        ngx_log_error(NGX_LOG_INFO, sess->connection->log, 0, "xtomp invalid host header");
        sess->quit = 1;
        xtomp_response_error_syntax(sess, sess->connection);
        xtomp_send(sess->connection->write);
        return NGX_ERROR;
    }

    if ( rc == NGX_ERROR ) {
        sess->quit = 1;
        xtomp_response_error_general(sess, sess->connection);
        xtomp_send(sess->connection->write);
        return NGX_ERROR;
    }

/*
    if ( sess->headers_in.server.len ) {
        return NGX_OK;
    }

    sess->headers_in.server = host;
*/
    return NGX_OK;
}


static ngx_int_t
xtomp_headers_login(xtomp_session_t *sess, ngx_table_elt_t *h, ngx_uint_t offset)
{

    if ( sess->headers_in.login == NULL ) {
        sess->headers_in.login = h;
        xtomp_headers_cpy(h, NULL);
    }
    else {
        xtomp_free(h);
        return NGX_OK;
    }

    // dont copy login name till auth has finished

    return NGX_OK;
}


