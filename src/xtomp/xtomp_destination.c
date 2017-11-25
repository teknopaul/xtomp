/*
 * Contains code managing subscriptions to queues/topics.
 * 
 * Copyright (C) Teknopaul 
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>


static void xtomp_destination_clean_messages(xtomp_core_dest_conf_t *dest);

ngx_int_t
xtomp_destination_put(xtomp_core_dest_conf_t *dest, xtomp_message_t *m_from)
{
    ngx_int_t           rc, i, wrc;
    ngx_uint_t          msg_id;
    xtomp_message_t    *m_to;

    if ( dest->max_messages == dest->q_size ) {
        return XTOMP_Q_FLUP;
    }

    // take ownership of m
    m_to = xtomp_message_create(dest);
    if ( m_to == NULL ) {
        return NGX_ERROR;
    }
    m_to->dest = 1;

    rc = xtomp_message_defrag(m_to, m_from);
    if ( rc == NGX_ERROR ) {
        xtomp_message_free(m_to);
        return NGX_ERROR;
    }

    // take ownership of headers
    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {

        if ( m_from->hdrs[i] ) {
            m_to->hdrs[i] = m_from->hdrs[i];
            m_from->hdrs[i] = NULL;
        }

    }


    msg_id = dest->message_idx++;

    if ( m_from->id ) {
        m_to->id = m_from->id;
    } else {
        m_to->id = msg_id;
    }

    dest->queue[dest->q_tail++] = m_to;
    dest->q_size++;

    // tail at the end of the q
    if ( dest->q_tail == dest->max_messages ) {
        dest->q_tail = 0;
    }

    if ( dest->log_messages_flag ) {
        wrc = xtomp_log_store(m_to); // TODO async this
        if ( wrc != NGX_OK ) return NGX_ERROR;
    }

    xtomp_destination_send(dest, m_to); // TODO async this

    return NGX_OK;
}

xtomp_message_t*
xtomp_destination_pop(xtomp_core_dest_conf_t *dest)
{
    xtomp_message_t *m;

    if ( dest->q_size == 0 ) {
        return NULL;
    }

    m = dest->queue[dest->q_head];
    dest->queue[dest->q_head] = NULL;
    dest->q_size--;
    dest->q_head++;
    if ( dest->q_head == dest->max_messages ) {
        dest->q_head = 0;
    }

    return m;
}

xtomp_message_t*
xtomp_destination_peek(xtomp_core_dest_conf_t *dest)
{
    if ( dest->q_size == 0 ) {
        return NULL;
    }

    return dest->queue[dest->q_head];
}

xtomp_message_t*
xtomp_destination_tail(xtomp_core_dest_conf_t *dest) {

    if ( dest->q_size == 0 ) {
        return NULL;
    }
    ngx_int_t pos;

    pos = dest->q_tail - 1;
    if ( pos < 0 ) {
        pos = dest->max_messages - 1;
    }
    return dest->queue[pos];
}

ngx_int_t
xtomp_destination_iterate(xtomp_core_dest_conf_t *dest, void* data, xtomp_dest_iter_pt callback)
{
    ngx_uint_t i, pos;
    xtomp_message_t *m;

    for ( i = 0, pos = dest->q_head ; i < dest->q_size ; i++ ) {
        m = dest->queue[pos++];
        if ( pos == dest->max_messages ) pos = 0;

        if ( callback(dest, data, m) != NGX_AGAIN ) return NGX_ERROR;
    }

    return NGX_OK;
}





// TODO test me of replace me with pointers

xtomp_core_dest_conf_t*
xtomp_destination_find(xtomp_core_srv_conf_t  *cscf, ngx_str_t *dest_name)
{
    size_t                       i;
    xtomp_core_dest_conf_t  *dest;
    xtomp_core_dest_conf_t **destinations;

    destinations = cscf->destinations;

    for ( i = 0 ; i < XTOMP_MAX_DESTINATIONS ; i++ ) {

        dest = destinations[i];
        if ( dest ) {
            if ( dest_name->len == dest->name.len &&
                 ngx_strncmp(dest_name->data, dest->name.data, dest->name.len) == 0 ) {
                return dest;
            }
        }
        else break;

    }

    return NULL;
}



/**
 * subscribe
 */
ngx_int_t
xtomp_destination_subscribe(xtomp_session_t *s, ngx_connection_t *c, ngx_str_t *dest_name, ngx_int_t id, ngx_uint_t ack, xtomp_subscriber_t **sub_out)
{
    xtomp_core_srv_conf_t  *cscf;
    xtomp_core_dest_conf_t *dest;
    xtomp_subscriber_t     *sub;

    cscf = xtomp_get_module_srv_conf(s, xtomp_core_module);
    dest = xtomp_destination_find(cscf, dest_name);

    if ( dest == NULL ) {
        ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, c->log, 0, "dest unknown: %V", dest_name);
        return XTOMP_DESTINATION_UNKNOWN;
    }

    if ( dest->size == dest->max_connections ) {
        ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, c->log, 0, "dest flup: %d", dest->size);
        return XTOMP_DESTINATION_FLUP;
    }

    if ( s->ws && dest->web_read_block_flag ) {
        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, c->log, 0, "dest block");
        return XTOMP_DESTINATION_BLOCKED;
    }

    sub = xtomp_destination_create_subscription(dest, s, id, ack);
    if ( sub == NULL ) {
        return NGX_ERROR;
    }
    if ( dest->filter_flag == xtomp_filter_on && sub->filter == NULL ) {
        xtomp_destination_free_subscription(sub);
        return NGX_ERROR;
    }


    if ( dest->filter_flag == xtomp_filter_on ) {
        xtomp_destination_subscribe_hash(dest, sub);
    }
    else {
        xtomp_destination_subscribe_list(dest, sub);
    }

    if (sub_out) *sub_out = sub;

    ngx_log_debug2(NGX_LOG_DEBUG_XTOMP, c->log, 0, "xtomp subs to: %V sz=%ui", dest_name, dest->size);

    return NGX_OK;
}

/*
 * unsubscribe, unlink this subscription and free the memory 
 */
void
xtomp_destination_unsubscribe(xtomp_subscriber_t *sub)
{
    xtomp_core_dest_conf_t *dest;

    dest = sub->dest;

    if ( dest->filter_flag == xtomp_filter_off ) {
        xtomp_destination_unsubscribe_list(dest, sub);
    }
    else {
        xtomp_destination_unsubscribe_hash(dest, sub);
    }

    xtomp_destination_free_subscription(sub);

}

/*
 * Kick off message sending
 */
ngx_int_t
xtomp_destination_send(xtomp_core_dest_conf_t *dest, xtomp_message_t *m)
{
    ngx_str_t *filter;

    if ( dest->size == 0 && dest->no_subs_flag == 1 ) {
        xtomp_destination_nack(dest, m);
        return NGX_OK;
    }

    if ( dest->filter_flag == xtomp_filter_off ) {

        return xtomp_destination_send_list(dest, m);
    }
    else {

        filter = xtomp_message_get_header(m, &dest->filter_hdr);
        if ( filter == NULL ) {
            return NGX_ERROR;
        }

        return xtomp_destination_send_hash(dest, m, filter);
    }
}


static ngx_int_t
xtomp_destination_deliver_message(xtomp_core_dest_conf_t *dest, void* data, xtomp_message_t *m)
{
    xtomp_subscriber_t *sub;
    xtomp_session_t    *sess;

    sub = (xtomp_subscriber_t *)data;
    sess = sub->sess;

    if ( m->delivered < dest->min_delivery ) {
        xtomp_message_mq_push(sess, dest, sub->id, m);
    }

    return NGX_AGAIN;
}
/*
 * Deliver all queued messages to recently subscribed connection
 */
ngx_int_t
xtomp_destination_deliver(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub)
{
    ngx_int_t rc;

    rc = xtomp_destination_iterate(dest, sub, xtomp_destination_deliver_message);

    return rc;
}





/*
 * Clean sent messages from front of the queue
 * TODO we should clean all sent message, we would have to juggle the ring buffer
 */
static void
xtomp_destination_clean_messages(xtomp_core_dest_conf_t *dest)
{
    xtomp_message_t *m;

    m = xtomp_destination_peek(dest);
    while ( m != NULL && m->sent == 1 && m->delivered >= dest->min_delivery ) {
        m = xtomp_destination_pop(dest);
        if ( m->dest ) {
            xtomp_message_free(m);
        }
        else {
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, dest->log, 0, "dest mem bug");
        }
        m = xtomp_destination_peek(dest);
    }

}

ngx_int_t
xtomp_destination_ack(xtomp_core_dest_conf_t  *dest, xtomp_message_t *m)
{

    ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, dest->log, 0, "xtomp refs=%l", m->refs);

    m->delivered++;

    if ( m->refs == 0 ) {
        m->sent = 1;
        xtomp_destination_clean_messages(dest);
    }

    return NGX_OK;
}

/*
 * For a memtop NACK is the same as ACK, dont send me this message again.
 */
ngx_int_t
xtomp_destination_nack(xtomp_core_dest_conf_t  *dest, xtomp_message_t *m)
{
    return xtomp_destination_ack(dest, m);
}

static void
xtomp_destination_log(ngx_event_t *log_evt)
{
    xtomp_core_dest_conf_t  *dest;

    dest = log_evt->data;

// TODO move this to its own status

// TODO this should be a STOMP message on a stats q
    ngx_uint_t delta = dest->message_idx - dest->last_message_idx;
    dest->last_message_idx = dest->message_idx;
    ngx_log_error(NGX_LOG_INFO, log_evt->log, 0, "xtomp d=%s s=%l, q=%l, Δ=%l, Σ=%l", dest->name.data, dest->size, dest->q_size, delta, dest->message_idx);

    if ( log_evt->timer_set ) {
        ngx_del_timer(log_evt);
    }
    ngx_add_timer(log_evt, 60000);

}

ngx_int_t
xtomp_destination_logger(xtomp_core_dest_conf_t *dest)
{
    ngx_event_t *log_evt = xtomp_perm_calloc(1, sizeof(ngx_event_t));
    if ( log_evt == NULL ) {
        return NGX_ERROR;
    }

    log_evt->data = dest;
    log_evt->handler = xtomp_destination_log;
    log_evt->log = dest->log;

    ngx_add_timer(log_evt, 60000);
    log_evt->timer_set = 1;

    return NGX_OK;
}


/*
 * Check that writing to this destination is permitted
 */
ngx_int_t
xtomp_destination_check_write(xtomp_session_t *sess, ngx_str_t *dest_name)
{
    xtomp_core_srv_conf_t  *cscf;
    xtomp_core_dest_conf_t *dest;



    cscf = xtomp_get_module_srv_conf(sess, xtomp_core_module);
    dest = xtomp_destination_find(cscf, dest_name);

    if ( dest == NULL ) {
        return XTOMP_DESTINATION_UNKNOWN;
    }

    if ( sess->ws && dest->web_write_block_flag ) {
        return XTOMP_DESTINATION_BLOCKED;
    }

    return NGX_OK;
}














