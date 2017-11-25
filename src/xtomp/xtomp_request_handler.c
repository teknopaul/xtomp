
/*
 * Contains code for acting on STOMP messages.
 * 
 * TODO rename to xtomp_command_handler.c
 * 
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>

static ngx_int_t xtomp_request_create_buffer(xtomp_session_t *sess, ngx_connection_t *c);
static ngx_int_t xtomp_request_create_bufout(xtomp_session_t *sess, ngx_connection_t *c);
static void xtomp_request_reset_buffer_soft(xtomp_session_t *sess);
static void xtomp_request_reset_buffer_hard(xtomp_session_t *sess);

// Message processing
static void xtomp_request_syntax_error(xtomp_session_t *sess, ngx_connection_t *c);
static void xtomp_request_connect(xtomp_session_t *sess, ngx_connection_t *c);
static void xtomp_request_disconnect(xtomp_session_t *sess, ngx_connection_t *c);
static void xtomp_request_subscribe(xtomp_session_t *sess, ngx_connection_t *c);
static void xtomp_request_unsubscribe(xtomp_session_t *sess, ngx_connection_t *c);
static void xtomp_request_send(xtomp_session_t *sess, ngx_connection_t *c, ngx_event_t *rev);
static void xtomp_request_ack(xtomp_session_t *sess, ngx_connection_t *c);
static void xtomp_request_nack(xtomp_session_t *sess, ngx_connection_t *c);


//static ngx_int_t xtomp_request_discard_command(xtomp_session_t *sess, ngx_connection_t *c, char *err);
//static void xtomp_request_log_rejected_command(xtomp_session_t *sess, ngx_connection_t *c, char *err);

// TODO delete
static ngx_str_t request_unavailable = ngx_string("[UNAVAILABLE]");
static ngx_str_t request_tempunavail = ngx_string("[TEMPUNAVAIL]");

//static ngx_str_t ack_auto = ngx_string("auto");
static ngx_str_t ack_client = ngx_string("client");
//static ngx_str_t ack_client_individual = ngx_string("client-individual");

void
xtomp_request_init_session(xtomp_session_t *sess, ngx_connection_t *c)
{

    xtomp_core_srv_conf_t  *cscf;
    cscf = xtomp_get_module_srv_conf(sess, xtomp_core_module);

    sess->host = request_unavailable;
    c->read->handler = xtomp_request_init_protocol;

#if (NGX_HAVE_UNIX_DOMAIN)
    if ( c->sockaddr->sa_family == AF_UNIX ) {
        sess->host = request_tempunavail;
    }
#endif

    ngx_add_timer(c->read, cscf->timeout);

    if ( ngx_handle_read_event(c->read, 0) != NGX_OK ) {
        xtomp_close_connection(c);
    }

}


void
xtomp_request_init_protocol(ngx_event_t *rev)
{

    ngx_connection_t *c;
    xtomp_session_t  *sess;

    c = rev->data;

    c->log->action = "in init state";

    if ( rev->timedout ) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "xtomp client init timed out");
        c->timedout = 1;
        xtomp_close_connection(c);
        return;
    }

    sess = c->data;

    if ( sess->buffer == NULL ) {
        if (xtomp_request_create_buffer(sess, c) != NGX_OK) {
            return;
        }
    }
    if ( sess->bufout == NULL ) {
        if (xtomp_request_create_bufout(sess, c) != NGX_OK) {
            return;
        }
    }

    sess->xtomp_state = xtomp_conn_start;
    c->read->handler = xtomp_request_process_commands;

    xtomp_request_process_commands(rev);
}


static ngx_int_t
xtomp_request_create_buffer(xtomp_session_t *sess, ngx_connection_t *c)
{
    xtomp_core_srv_conf_t  *sscf;

    sscf = xtomp_get_module_srv_conf(sess, xtomp_core_module);

    sess->buffer = ngx_create_temp_buf(c->pool, sscf->client_buffer_size);
    if ( sess->buffer == NULL ) {
        sess->quit = 1;
        xtomp_response_error_general(sess, c);
        xtomp_send(sess->connection->write);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
xtomp_request_create_bufout(xtomp_session_t *sess, ngx_connection_t *c)
{
    xtomp_core_srv_conf_t  *sscf;

    sscf = xtomp_get_module_srv_conf(sess, xtomp_core_module);

    sess->bufout = ngx_palloc(c->pool, sscf->client_bufout_size);
    if ( sess->bufout == NULL ) {
        sess->quit = 1;
        xtomp_response_error_general(sess, c);
        xtomp_send(sess->connection->write);
        return NGX_ERROR;
    }
    sess->bufout[0] = 0;

    return NGX_OK;
}


void
xtomp_request_process_commands(ngx_event_t *rev)
{
    ngx_int_t               rc;
    ngx_connection_t       *c;
    xtomp_session_t        *sess;

    c = rev->data;
    sess = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp process command");


    if ( rev->timedout ) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "xtomp read timeout");
        c->timedout = 1;
        xtomp_close_connection(c);
        return;
    }

    // TODO why do we care?
    if ( sess->out.len ) {
        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp send handler busy");
        sess->blocked = 1;
        return;
    }

    sess->blocked = 0;

    rc = xtomp_read_command(sess, c);

    if ( rc == NGX_AGAIN || rc == NGX_ERROR || rc == NGX_DONE ) {
        return;
    }

    if ( rc == XTOMP_HDR_FLUP ) {
        sess->quit = 1;
        xtomp_response_error_message(sess, c, "hdr flup");
        xtomp_send(c->write);
        return;
    }

    if ( rc == XTOMP_PARSE_INVALID_COMMAND ) {
        switch (sess->xtomp_state) {

        case xtomp_conn_start:
        case xtomp_conn_initial:
            sess->quit = 1;
            xtomp_request_syntax_error(sess, c);
            return;

        case xtomp_conn_connected:
        case xtomp_conn_subscribed:
            // TODO recover
            //xtomp_request_discard_frame(rev);
            sess->quit = 1;
            xtomp_request_syntax_error(sess, c); 
            return;

        case xtomp_conn_disconnected:
        case xtomp_conn_errored:
            sess->quit = 1;
            xtomp_close_connection(c);
            return;
        default:
            // BUG?
            sess->quit = 1;
            xtomp_close_connection(c);
            return;
        }
    }

    if ( rc == NGX_OK ) {
        switch (sess->xtomp_state) {

        case xtomp_conn_start:
        case xtomp_conn_initial:

            switch (sess->command) {

            case STOMP_COMMAND_CONNECT:
                xtomp_request_connect(sess, c);
                return;

            case STOMP_COMMAND_DISCONNECT:
                xtomp_request_disconnect(sess, c);
                return;

            default:
                xtomp_request_syntax_error(sess, c);
                return;
            }

        case xtomp_conn_connected:
        case xtomp_conn_subscribed:

            switch (sess->command) {

            case STOMP_COMMAND_SUBSCRIBE:
                xtomp_request_subscribe(sess, c);
                return;

            case STOMP_COMMAND_UNSUBSCRIBE:
                xtomp_request_unsubscribe(sess, c);
                return;

            case STOMP_COMMAND_SEND:
                xtomp_request_send(sess, c, rev);
                return;

            case STOMP_COMMAND_ACK:
                xtomp_request_ack(sess, c);
                return;

            case STOMP_COMMAND_NACK:
                xtomp_request_nack(sess, c);
                return;

            case STOMP_COMMAND_DISCONNECT:
                xtomp_request_disconnect(sess, c);
                return;

            default:
                xtomp_request_syntax_error(sess, c);
                return;
            }

        case xtomp_conn_disconnected:
            // BUG??
            sess->quit = 1;
            xtomp_close_connection(c);
            return;

        case xtomp_conn_errored:
            sess->quit = 1;
            xtomp_response_error_general(sess, c);
            xtomp_send(sess->connection->write);
            return;

        default:
            // BUG?
            sess->quit = 1;
            xtomp_close_connection(c);
            return;
        }

    }

}

/*
 * reset buffer to pos = start, loosing any buffered data
 */
static void
xtomp_request_reset_buffer_hard(xtomp_session_t *sess)
{
    sess->buffer->pos = sess->buffer->start;
    sess->buffer->last = sess->buffer->start;
    sess->buffer->pos[0] = '*';
}

/*
 * reset buffer to pos = start, shifting any buffered data
 */
static void
xtomp_request_reset_buffer_soft(xtomp_session_t *sess)
{
    ngx_int_t  len;

    len = sess->buffer->last - sess->buffer->pos;
    if ( len == 0 ) {
        xtomp_request_reset_buffer_hard(sess);
    }
    else if ( len < 0 ) {
        ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, sess->connection->log, 0, "rst buf len < 0" , len);
    }
    else {
        ngx_memmove(sess->buffer->start, sess->buffer->pos, len);
        sess->buffer->pos = sess->buffer->start;
        sess->buffer->last = sess->buffer->start + len;
    }
}
/**
 * respond to a syntax error
 */
static void
xtomp_request_syntax_error(xtomp_session_t *sess, ngx_connection_t *c)
{
    xtomp_response_error_syntax(sess, c);
    xtomp_send(c->write);
}

/**
 * respond to a CONNECT, noop unless a recepit was requested.
 */
static void
xtomp_request_connect(xtomp_session_t *sess, ngx_connection_t *c)
{

    if ( xtomp_auth_login_passcode(sess, c) != NGX_OK ) {
        xtomp_response_error_message(sess, c, "auth err");
        sess->quit = 1;
        xtomp_send(c->write);
        return;
    }

    if ( xtomp_auth_sha(sess, c) != NGX_OK ) {
        xtomp_response_error_message(sess, c, "sha auth err");
        sess->quit = 1;
        xtomp_send(c->write);
        return;
    }

    if ( xtomp_auth_set_login_name(sess, c) != NGX_OK ) {
        xtomp_response_error_message(sess, c, "mem err");
        sess->quit = 1;
        xtomp_send(c->write);
        return;
    }

    if ( xtomp_ecg_connect(sess) != NGX_OK ) {
        xtomp_response_error_message(sess, c, "ecg err");
        sess->quit = 1;
        xtomp_send(c->write);
        return;
    }
    xtomp_ecg_set_read_timeout(sess, sess->connection->read);

    // For now just answer version, we should negotiate versions here.

    sess->xtomp_state = xtomp_conn_connected;

    xtomp_request_reset_buffer_soft(sess);
    xtomp_headers_unset(sess);

    xtomp_response_connect(sess, c);
    xtomp_send(c->write);

}

/**
 * respond to a DISCONNECT.
 */
static void
xtomp_request_disconnect(xtomp_session_t *sess, ngx_connection_t *c)
{

    xtomp_close_connection(c);
    return;

}

/**
 * respond to a SUBSCRIBE, no reply sent unless a recepit was requested.
 */
static void
xtomp_request_subscribe(xtomp_session_t *sess, ngx_connection_t *c)
{
    ngx_int_t            rc, id, ack;
    ngx_str_t           *dest_name;
    xtomp_subscriber_t  *sub;

    if ( sess->subs_size == XTOMP_MAX_SUBS ) {
        xtomp_response_error_message(sess, c, "subs flup");
        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        xtomp_send(c->write);
        return;
    }

    if ( sess->headers_in.destination == NULL ){
        xtomp_response_error_dest_unknown(sess, c);
        xtomp_send(c->write);
        return;
    }

    dest_name = &sess->headers_in.destination->value;

    if ( sess->headers_in.id ) {
        id = ngx_atoi(sess->headers_in.id->value.data, sess->headers_in.id->value.len);
        if ( id == NGX_ERROR ) {
            ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp non-numeric id %V", sess->headers_in.id->value);
            id = 0;
        }
    }
    else {
        id = 1;
    }

    ack = xtomp_ack_auto;
    if ( sess->headers_in.ack ) {
        if ( xtomp_strcmp( &sess->headers_in.ack->value , &ack_client) == 0 ) {
            ack = xtomp_ack_client;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp sub %V:%i", dest_name, id);

    rc = xtomp_destination_subscribe(sess, c, dest_name, id, ack, &sub);
    switch (rc) {

    case NGX_ERROR:
    case XTOMP_DESTINATION_FLUP:
        xtomp_response_error_message(sess, c, "dest flup");

        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        xtomp_send(c->write);
        return;

    case XTOMP_DESTINATION_BLOCKED:
        xtomp_response_error_message(sess, c, "blocked");

        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        xtomp_send(c->write);
        return;

    case XTOMP_DESTINATION_UNKNOWN:
        xtomp_response_error_dest_unknown(sess, c);

        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        xtomp_send(c->write);
        return;

    case NGX_OK:
        sess->xtomp_state = xtomp_conn_subscribed;

        rc = xtomp_session_subs_add(sess, sub);
        if ( rc == XTOMP_SUBS_FLUP ) {
            xtomp_destination_unsubscribe(sub);
            xtomp_response_error_message(sess, c, "subs flup");

            xtomp_request_reset_buffer_soft(sess);
            xtomp_headers_unset(sess);
            xtomp_send(c->write);
            return;
        }

        // replay queue
        if ( sub->dest->min_delivery ) {
            xtomp_destination_deliver(sub->dest, sub);
        }

        rc = xtomp_response_receipt(sess, c);
        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        if ( rc == NGX_OK || sess->mq_size ) {
            xtomp_send(c->write);
        }

        xtomp_ecg_set_read_timeout(sess, sess->connection->read);
        return;

    default:
        xtomp_response_error_general(sess, c);

        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        xtomp_send(c->write);
        return;
    }
}

/**
 * respond to an UNSUBSCRIBE message from the client
 */
static void
xtomp_request_unsubscribe(xtomp_session_t *sess, ngx_connection_t *c)
{
    ngx_int_t               id, rc;
    ngx_str_t              *dest_name;
    xtomp_subscriber_t     *sub;

    if (sess->headers_in.destination == NULL ){
        xtomp_response_error_dest_unknown(sess, c);

        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        xtomp_send(c->write);
        return;
    }

    dest_name = &sess->headers_in.destination->value;

    if (sess->headers_in.id) {
        id = ngx_atoi(sess->headers_in.id->value.data, sess->headers_in.id->value.len);
        if (id == NGX_ERROR) {
            // BUG error and reply
            ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp non-numeric id %V", sess->headers_in.id->value);
            id = 0;
        }
    }
    else {
        id = 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp unsub %V", dest_name);

    sub = xtomp_session_subs_find(sess, dest_name, id);

    xtomp_ecg_set_read_timeout(sess, sess->connection->read);

    if (sub != NULL) {

        xtomp_session_subs_remove(sess, sub);
        xtomp_destination_unsubscribe(sub);

        if (sess->subs_size == 0 ) sess->xtomp_state = xtomp_conn_connected;

        rc = xtomp_response_receipt(sess, c);

        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        if (rc == NGX_OK ) xtomp_send(c->write);
        return;
    }
    else {
        xtomp_response_error_dest_unknown(sess, c);

        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        xtomp_send(c->write);
        return;
    }

}

/**
 * respond to a SEND
 */
static void
xtomp_request_send(xtomp_session_t *sess, ngx_connection_t *c, ngx_event_t *rev)
{
    ngx_int_t   rc;
    off_t       content_length;

    if ( sess->headers_in.destination == NULL || sess->headers_in.destination->value.data == NULL) {
        xtomp_response_error_dest_unknown(sess, c);
        // cant recover without reading message
        xtomp_request_reset_buffer_hard(sess);
        xtomp_headers_unset(sess);
        sess->quit = 1;
        xtomp_send(c->write);
        return;
    }

    rc = xtomp_destination_check_write(sess, &sess->headers_in.destination->value);

    if ( rc == XTOMP_DESTINATION_UNKNOWN ) {
        xtomp_response_error_dest_unknown(sess, c);
        // cant recover without reading message
        xtomp_request_reset_buffer_hard(sess);
        xtomp_headers_unset(sess);
        sess->quit = 1;
        xtomp_send(c->write);
        return;
    }
    else if ( rc == XTOMP_DESTINATION_BLOCKED ) {
        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp send blocked");
        xtomp_response_error_message(sess, c, "blocked");
        // cant recover without reading message
        xtomp_request_reset_buffer_hard(sess);
        xtomp_headers_unset(sess);
        sess->quit = 1; 
        xtomp_send(c->write);
        return;
    }
    else if (rc != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp BUG in send");
        sess->quit = 1; 
        xtomp_send(c->write);
        return;
    }

    if ( sess->headers_in.content_length != NULL ) {

        content_length = ngx_atoi(sess->headers_in.content_length->value.data, sess->headers_in.content_length->value.len);

        if ( content_length == NGX_ERROR || content_length < 1 ) {

            xtomp_response_error_message(sess, c, "len not +int");

            xtomp_request_reset_buffer_soft(sess);
            xtomp_headers_unset(sess);
            xtomp_send(c->write);
            return;
        }
        else {
            sess->expected_len = content_length;
        }

    }
    else {
        sess->expected_len = -1;
    }

    sess->state = 0;
    c->read->handler = xtomp_request_process_body;
    xtomp_request_process_body(rev);

}

/*
 * Find mq by id header for ACK and NACK
 * Handles recepits too.
 */
static xtomp_mq_t*
xtomp_request_mq_find(xtomp_session_t *sess, ngx_connection_t *c)
{
    ngx_int_t                   id, rc;
    xtomp_mq_t             *mq;

    id = NGX_ERROR;
    if ( sess->headers_in.id ) {
        id = ngx_atoi(sess->headers_in.id->value.data, sess->headers_in.id->value.len);
    }

    if ( id == NGX_ERROR ) {
        xtomp_response_error_message(sess, c, "id not opt");

        xtomp_request_reset_buffer_soft(sess);
        xtomp_headers_unset(sess);
        xtomp_send(c->write);
        return NULL;
    }

    mq = xtomp_message_mq_find(sess, id);

    xtomp_request_reset_buffer_soft(sess);
    rc= xtomp_response_receipt(sess, c);
    xtomp_headers_unset(sess);
    if (rc == NGX_OK ) xtomp_send(c->write);

    return mq;

}

/*
 * handle an ACK from a client, receved to confirm a published request_message
 * was received.
 */
static void
xtomp_request_ack(xtomp_session_t *sess, ngx_connection_t *c)
{
    xtomp_mq_t             *mq;

    mq = xtomp_request_mq_find(sess, c);
    if ( mq != NULL ) {
        xtomp_destination_ack(mq->dest, mq->message);
    }

    xtomp_ecg_set_read_timeout(sess, sess->connection->read);
}

/*
 * handle an NACK from a client, receved to confirm a published request_message
 * was received.
 */
static void
xtomp_request_nack(xtomp_session_t *sess, ngx_connection_t *c)
{
    xtomp_mq_t             *mq;

    mq = xtomp_request_mq_find(sess, c);
    if ( mq != NULL ) {
        xtomp_destination_nack(mq->dest, mq->message);
    }

    xtomp_ecg_set_read_timeout(sess, sess->connection->read);
}

// TODO only do this if we were not reading according to content-length
void
xtomp_request_discard_frame(ngx_event_t *rev)
{
    ngx_int_t rc;
    ngx_connection_t       *c;
    xtomp_session_t        *sess;
    xtomp_core_srv_conf_t  *cscf;

    c = rev->data;
    sess = c->data;
    cscf = xtomp_get_module_srv_conf(sess, xtomp_core_module);

    rc = xtomp_request_parse_discard_frame(sess);
    switch(rc) {
        case NGX_OK:
            xtomp_request_reset_buffer_soft(sess);
            c->read->handler = xtomp_request_process_commands;
            break;
        case NGX_AGAIN:
            c->read->handler = xtomp_request_discard_frame;
            break;
        default:
            // BUG?
            break;
    }

    ngx_add_timer(c->read, cscf->timeout);

    if ( ngx_handle_read_event(c->read, 0) != NGX_OK ) {
        xtomp_close_connection(c);
    }

}
