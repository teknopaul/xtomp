/*
 * Contains code for uploading SEND bodys, i.e. handling message content.
 * 
 * Reads to main memory (memtop), could be more cleverer and sendfile() to shrdmem.
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



static void 
xtomp_request_process_body_error(xtomp_session_t *sess, ngx_connection_t *c)
{
    xtomp_response_error_general(sess, c);
    // per STOMP spec, any SEND error terminates the connection :(
    sess->quit = 1;
    xtomp_send(c->write);
}

// TODO rst are duplicated in request_body.c and request_handler.c
static void
xtomp_request_reset_buffer_hard(xtomp_session_t *sess)
{
    sess->buffer->pos = sess->buffer->start;
    sess->buffer->last = sess->buffer->start;
    sess->buffer->pos[0] = '*';
}
static void
xtomp_request_reset_buffer_soft(xtomp_session_t *sess)
{
    ngx_int_t  len;

    len = sess->buffer->last - sess->buffer->pos;
    if ( len == 0 ) {
        xtomp_request_reset_buffer_hard(sess);
    }
    else if ( len < 0 ) {
        ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, sess->connection->log, 0, "xtomp rst buf len < 0" , len);
    }
    else {
        ngx_memmove(sess->buffer->start, sess->buffer->pos, len);
        sess->buffer->pos = sess->buffer->start;
        sess->buffer->last = sess->buffer->start + len;
    }
}

static ngx_uint_t 
xtomp_request_read_body_data(xtomp_session_t *sess, ngx_connection_t *c) 
{
    ssize_t     n;
    ngx_int_t   rc;
    u_char     *recv_start;

    recv_start = sess->buffer->last;
    n = c->recv(c, sess->buffer->last, sess->buffer->end - sess->buffer->last);
    if ( n == NGX_ERROR || n == 0 ) {
        xtomp_close_connection(c);
        return NGX_ERROR;
    }

    // I think NGX_AGAIN means nothing was read but the connection is OK for more reading
    if ( n == NGX_AGAIN ) {
        if ( ngx_handle_read_event(c->read, 0) != NGX_OK ) {
            sess->quit = 1;
            xtomp_response_error_general(sess, c);
            xtomp_send(sess->connection->write);
            return NGX_ERROR;
        }

        xtomp_request_reset_buffer_hard(sess);
        return NGX_AGAIN;
    }

    if ( n > 0 ) {
        sess->buffer->last += n;
    }
    // TODO other error codes?

    // WEBSOCKETS:
    if ( sess->ws ) {
        rc = xtomp_ws_demunge(sess, recv_start);
        if ( rc != NGX_OK ) {
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp demunge err");
        }
        return rc;
    }

    return NGX_OK;
}

static void
xtomp_request_set_msg_id(xtomp_session_t *sess, xtomp_message_t *m)
{
    ngx_int_t  id;

    if ( sess->trusted && sess->headers_in.id != NULL && sess->headers_in.id->value.data != NULL ) {
        id = ngx_atoi(sess->headers_in.id->value.data, sess->headers_in.id->value.len);
        if ( id != NGX_ERROR ) {
            m->id = id;
        }
    }
}
/**
 * Read body, if we have content-length read until we hit that then validate the
 * existence of a NUL at the end of the frame.
 * If we don't have length read text until the first NUL.
 */
void
xtomp_request_process_body(ngx_event_t *rev)
{
    u_char                  ch, *p;
    ngx_int_t               rc,rcc;
    ngx_connection_t       *c;
    xtomp_session_t        *sess;
    xtomp_message_t        *m;
    xtomp_core_srv_conf_t  *cscf;
    xtomp_core_dest_conf_t *dest;
    ngx_str_t               in_str;
    off_t                   expected_len, overflow;
    size_t                  exp_len;
    ngx_str_t              *dest_name;

    c = rev->data;
    sess = c->data;

    cscf = xtomp_get_module_srv_conf(sess, xtomp_core_module);

    if ( sess->message == NULL ) {

        dest_name = &sess->headers_in.destination->value;
        dest = xtomp_destination_find(cscf, dest_name);
        if ( dest == NULL ) {
            xtomp_response_error_dest_unknown(sess, c);
            sess->quit = 1;
            xtomp_send(c->write);
            return;
        }
        if ( sess->expected_len != -1 && dest->max_message_size < (ngx_uint_t)sess->expected_len ) {
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp msg flup");
            xtomp_response_error_message(sess, c, "msg flup");
            sess->quit = 1;
            xtomp_send(c->write);
            return;
        }

        m = xtomp_message_create(dest);
        if ( m == NULL ) {
            xtomp_request_process_body_error(sess, c);
            sess->quit = 1;
            xtomp_send(c->write);
            return;
        }
        m->conn = 1;
        m->destination = &dest->name;
        xtomp_request_set_msg_id(sess, m);

        xtomp_headers_move(m, sess);

        sess->message = m;

    }
    else {
        m = sess->message;
        dest_name = m->destination;
        // TODO cache this lookup
        dest = xtomp_destination_find(cscf, dest_name);
    }


    ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp process body");

    if ( rev->timedout ) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "xtomp body read timeout");
        c->timedout = 1;
        xtomp_message_free(sess->message);
        sess->message = NULL;
        xtomp_close_connection(c);
        return;
    }

    // if we were called directly from request_handler.c with pipelined data
    if ( sess->buffer->pos < sess->buffer->last ) {
        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, sess->connection->log, 0, "xtomp pipelined");
        rc = NGX_OK;
    }
    else {
        rc = xtomp_request_read_body_data(sess, c);
    }

    while ( rc == NGX_OK ) {

        enum {
            sw_body = 0,
            sw_almost_end,
            sw_end
        } state;

        state = sess->state;

        expected_len = sess->expected_len;

        if ( expected_len > 0 ) {

            exp_len = (size_t)expected_len;
            // read up to content-length bytes

            if ( sess->message->length <= expected_len ) {

                in_str.data = sess->buffer->pos;
                in_str.len = sess->buffer->last - sess->buffer->pos; // everything we just read

                // at or past content-length
                overflow = sess->message->length + in_str.len - exp_len;
                if ( overflow >= 0 ) {
                    in_str.len -= overflow;
                    sess->buffer->pos += in_str.len;

                    if ( sess->buffer->pos < sess->buffer->last ) {

                        // validate frame terminator
                        ch = *sess->buffer->pos;
                        if ( 0 != ch ) {
                            xtomp_response_error_syntax(sess, c);
                            sess->quit = 1;
                            xtomp_send(c->write);
                            return;
                        }
                        else {
                            sess->buffer->pos++;
                            state = sw_end;
                        }
                    }
                    else {
                        // 0 byte marking end of frame not arrived yet
                        // potentially quite likely depending on how clients are written
                        // imagine send(headers); send(message); send(0); arriving as packets
                        state = sw_almost_end;
                    }
                }
                else {
                    state = sw_body;
                }
            }
            else {
                ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp msg overflow");
            }

        }
        else {

            // read text looking for a 0

            in_str.data = sess->buffer->pos;
            in_str.len = 0;

            for (p = sess->buffer->pos; p < sess->buffer->last; p++) {
                ch = *p;

                sess->buffer->pos++;
                if ( ch == 0 ) {
                    // end of frame
                    state = sw_end;
                    break;
                }
                in_str.len++;
            }
        }

        rcc = xtomp_message_add_chunk(m, &in_str);
        if ( rcc != NGX_OK ) {
            xtomp_request_process_body_error(sess, c);
            xtomp_headers_unset(sess);
            //xtomp_message_free(sess->message);
            //sess->message = NULL;
            return;
        }
        if ( dest->max_message_size < (ngx_uint_t)m->length ) {
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp msg flup");
            xtomp_response_error_message(sess, c, "msg flup");
            xtomp_headers_unset(sess);
            // WTF SIGSEV here if we free() but handler free()s OK and mallocs=0 after?
            // so commenting this seems OK but it would be nice to know why
            // xtomp_message_free(sess->message);
            // sess->message = NULL;
            sess->quit = 1;
            xtomp_send(c->write);
            return;
        }

        if ( state == sw_end ) {

            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp msg in");
            // state back to processing commands
            sess->state = 0;
            c->read->handler = xtomp_request_process_commands;
            xtomp_ecg_set_read_timeout(sess, rev);

            // drop the message on the queue
            rc = xtomp_destination_put(dest, m);

            xtomp_message_free(m);
            sess->message = NULL;

            if ( rc == XTOMP_Q_FLUP ) {
                xtomp_headers_unset(sess);
                ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp q flup");
                xtomp_request_reset_buffer_soft(sess);
                xtomp_response_error_message(sess, c, "q flup");
                sess->quit = 1;
                xtomp_send(c->write);
                return;
            }
            else if ( rc == NGX_ERROR ) {
                xtomp_headers_unset(sess);
                xtomp_response_error_general(sess, c);
                sess->quit = 1;
                xtomp_send(c->write);
                return;

            }

            // A-OK message received and understood

            xtomp_request_reset_buffer_soft(sess);
            rc = xtomp_response_receipt(sess, c);
            xtomp_headers_unset(sess);
            if (rc == NGX_OK ) xtomp_send(c->write);

            if ( sess->buffer->pos < sess->buffer->last ) {
                xtomp_request_process_commands(rev);
            }

            return;
        }
        // check if more data is readable via c->recv() & if so loop
        else if ( state < sw_end && sess->buffer->last == sess->buffer->end ) {
            xtomp_request_reset_buffer_hard(sess);
            rc = xtomp_request_read_body_data(sess, c);
            continue;
        }
        // WEBSOCKETS: munging fiddles buffer->last but we still want to loop if we read a full buffer's worth
        else if ( state < sw_end && sess->ws && sess->ws->frame_state == 4 /*sw_payload*/ && sess->ws->frame_pos < sess->ws->frame_len ) {
            xtomp_request_reset_buffer_hard(sess);
            rc = xtomp_request_read_body_data(sess, c);
            continue;
        }

        else {
            xtomp_request_reset_buffer_hard(sess);
            sess->state = state;
            // TODO set short read timeout
            //ngx_del_timer(c->read);
            //ngx_add_timer(c->read, 5000);
            return;
        }
    } // end while

    if ( rc == NGX_ERROR ) {
        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp body err");
        xtomp_response_error_message(sess, c, "body err");
        sess->quit = 1;
        xtomp_send(c->write);
        return;
    }

}



