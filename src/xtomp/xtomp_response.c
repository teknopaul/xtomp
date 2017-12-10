
/*
 * Contains code for writing STOMP reply messages.
 * 
 * Handles STOMP frames extra 0 byte except for MESSAGE
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



#define XTOMP_TERM_FRAME 1
#define XTOMP_HDRS       0

static const char response_connect_ack[] = "CONNECTED\nserver:xtomp/%ui.%ui\nversion:1.0\nsession:%ui\n";
static const char response_message_ack[] = "RECEIPT\nreceipt-id:%V\n\n\0";
static ngx_str_t response_error_general = { 24 , (u_char *) "ERROR\nmessage:general\n\n\0" };
static ngx_str_t response_error_syntax =  { 23 , (u_char *) "ERROR\nmessage:syntax\n\n\0" };
static ngx_str_t response_error_dest_unknown = { 36, (u_char *) "ERROR\nmessage:destination unknown\n\n\0" };
static const char response_error_message[] = "ERROR\nmessage:%s\n\n\0";

//WEBSOCKETS:
static const char response_http_upgrade[] = "HTTP/1.1 101 Switching Protocols\nUpgrade:websocket\nConnection:Upgrade\nSec-WebSocket-Protocol:stomp\nSec-WebSocket-Accept:%s\n";
static ngx_str_t response_http_500 = ngx_string("HTTP/1.1 500 Server Error\nserver:xtomp/0.2\n\n");
static ngx_str_t response_http_200 = ngx_string("HTTP/1.1 200 OK\nAccess-Control-Allow-Origin:*\nAccess-Control-Expose-Headers:server\nserver:xtomp/0.2\ncontent-length:0\nconnection:close\n\n");

static ngx_int_t
xtomp_response_check_bufout_size(xtomp_session_t *s, ngx_connection_t *c, size_t len)
{
    xtomp_core_srv_conf_t  *sscf;

    sscf = xtomp_get_module_srv_conf(s, xtomp_core_module);

    if ( len >= sscf->client_bufout_size ) {
        ngx_log_error(NGX_LOG_EMERG, c->log, 0, "xtomp bufout flup");
        xtomp_response_error_general(s, c);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * Create a message with a data buffer in it of size client_bufout_size.
 * WARN: len is set to MAX buffersize but data is not cleared.
 */
static xtomp_message_t *
xtomp_response_create_message(xtomp_session_t *s, ngx_connection_t *c)
{
    u_char                 *buf;
    xtomp_message_t        *m;
    xtomp_core_srv_conf_t  *sscf;

    sscf = xtomp_get_module_srv_conf(s, xtomp_core_module);

    m = xtomp_message_create(NULL);
    if ( m == NULL ) {
        return NULL;
    }
    m->conn = 1;
    m->chunks->data[0] = xtomp_calloc(1, sizeof(ngx_str_t));
    if ( m->chunks->data[0] == NULL ) {
        xtomp_free(m);
        xtomp_response_error_general(s, c);
        return NULL;
    }
    buf = xtomp_malloc(sscf->client_bufout_size);
    if ( buf == NULL ) {
        xtomp_free(m->chunks->data[0]);
        xtomp_message_free(m);
        xtomp_response_error_general(s, c);
        return NULL;
    }

    m->chunks->data[0]->data = buf;
    m->chunks->data[0]->data[0] = 0;
    m->chunks->data[0]->len = sscf->client_bufout_size;
    m->defragged = 1;
    m->chunks->pos = 0;

    return m;
}

static ngx_int_t
xtomp_response_push_message(xtomp_session_t *s, ngx_connection_t *c, xtomp_message_t *m, size_t len, ngx_int_t terminate)
{
    xtomp_mq_t      *mq;

    if ( xtomp_response_check_bufout_size(s, c, len) ) {
        return NGX_ERROR;
    }
    else {
        if ( terminate ) {
            // zero terminate the frame
            m->chunks->data[0]->data[len] = 0;
            m->chunks->data[0]->len = ++len;
        }
        else {
            m->chunks->data[0]->len = len;
        }
        mq = xtomp_message_mq_push(s, NULL, 0, m);
        if ( mq == NULL ) {
            xtomp_message_free(m);
            return NGX_ERROR;
        }
        mq->state = xtomp_mq_sent_hdrs;
        return NGX_OK;
    }
}

/**
 * Reply to a CONNECT.
 */
ngx_int_t
xtomp_response_connect(xtomp_session_t *s, ngx_connection_t *c)
{
    size_t           len;
    u_char          *buf;
    u_char          *rc;
    xtomp_message_t *m;

    m = xtomp_response_create_message(s, c);
    if ( m == NULL ) {
        return NGX_ERROR;
    }
    m->conn = 1;

    buf = m->chunks->data[0]->data;

    // TODO horrible code just increment buf
    rc = ngx_snprintf(buf, m->chunks->data[0]->len, response_connect_ack, XTOMP_VERSION_MAJOR, XTOMP_VERSION_MINOR, s->id);
    len = rc - buf;

    len += xtomp_ecg_write_header(s, buf, len);

    ngx_memcpy(buf + len,  "\n", 1);
    len++;

    return xtomp_response_push_message(s, c, m, len, 1);

}

/**
 * Reply to any message that had a receipt header.
 */
ngx_int_t
xtomp_response_receipt(xtomp_session_t *s, ngx_connection_t *c)
{
    size_t           len;
    u_char          *buf;
    u_char          *rc;
    xtomp_message_t *m;

    if ( s->headers_in.receipt == NULL ) {
        return NGX_DONE;
    }

    m = xtomp_response_create_message(s, c);
    if ( m == NULL ) {
        return NGX_ERROR;
    }
    m->conn = 1;

    buf = m->chunks->data[0]->data;

    rc = ngx_snprintf(buf, m->chunks->data[0]->len, response_message_ack, &s->headers_in.receipt->value);
    len = rc - buf;

    return xtomp_response_push_message(s, c, m, len, 1);

}

/**
 * Send a configurable error message
 */
ngx_int_t
xtomp_response_error_message(xtomp_session_t *s, ngx_connection_t *c, char *error_message)
{
    size_t           len;
    u_char          *buf;
    u_char          *rc;
    xtomp_message_t *m;

    m = xtomp_response_create_message(s, c);
    if ( m == NULL ) {
        return NGX_ERROR;
    }
    m->conn = 1;

    buf = m->chunks->data[0]->data;

    rc = ngx_snprintf(buf, m->chunks->data[0]->len, response_error_message, error_message);
    len = rc - buf;

    return xtomp_response_push_message(s, c, m, len, 1);
}

// WEBSOCKETS:

/**
 * Send HTTP upgrade message
 */
ngx_int_t
xtomp_response_http_upgrade(xtomp_session_t *s, ngx_connection_t *c)
{
    size_t           len;
    u_char          *buf;
    u_char          *rc;
    xtomp_message_t *m;

    m = xtomp_response_create_message(s, c);
    if ( m == NULL ) {
        return NGX_ERROR;
    }
    m->conn = 1;
    m->http = 1;

    buf = m->chunks->data[0]->data;

    rc = ngx_snprintf(buf, m->chunks->data[0]->len, response_http_upgrade, s->ws->accept);
    len = rc - buf;

    xtomp_free(s->ws->accept);
    s->ws->accept = NULL;

    return xtomp_response_push_message(s, c, m, len, 0);
}

static ngx_int_t
xtomp_response_error_fixed(xtomp_session_t *s, ngx_connection_t *c, ngx_str_t *message, ngx_int_t http)
{
    xtomp_message_t *m;
    xtomp_mq_t      *mq;

    m = xtomp_message_create(NULL);
    if ( m == NULL ) {
        return NGX_ERROR;
    }
    m->conn = 1;
    m->defragged = 1;
    m->constant = 1;
    m->chunks->data[0] = message;
    m->chunks->pos = 0;
    m->http = http;

    mq = xtomp_message_mq_push(s, NULL, 0, m);
    if ( mq == NULL ) {
        xtomp_message_free(m);
        return NGX_ERROR;
    }
    mq->state = xtomp_mq_sent_hdrs;

    return NGX_OK;
}

ngx_int_t
xtomp_response_error_syntax(xtomp_session_t *s, ngx_connection_t *c)
{
    return xtomp_response_error_fixed(s, c, &response_error_syntax, 0);
}

ngx_int_t
xtomp_response_error_general(xtomp_session_t *s, ngx_connection_t *c)
{
    return xtomp_response_error_fixed(s, c, &response_error_general, 0);
}

ngx_int_t
xtomp_response_error_dest_unknown(xtomp_session_t *s, ngx_connection_t *c)
{
    return xtomp_response_error_fixed(s, c, &response_error_dest_unknown, 0);
}

// WEBSOCKETS:
ngx_int_t
xtomp_response_http_500(xtomp_session_t *s, ngx_connection_t *c)
{
    return xtomp_response_error_fixed(s, c, &response_http_500, 1);
}
ngx_int_t
xtomp_response_http_200(xtomp_session_t *s, ngx_connection_t *c)
{
    return xtomp_response_error_fixed(s, c, &response_http_200, 1);
}


