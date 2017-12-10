/*
 * Contains code managing subscriptions to queues/topics.
 * 
 * Copyright (C) Teknopaul 
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



#define XTOMP_STATS_MSG_SZ      400
#define XTOMP_STATS_INTERVAL    60000

static const char response_stats[] = "{\n  \"dest\":\"%s\",\n  \"sz\":%l,\n  \"q\":%l,\n  \"Δ\":%l,\n  \"Σ\":%l\n}\n";
static const char response_cc[] = "{\n  \"cc\":{\n    \"sz\":%l,\n    \"up\":%l,\n    \"Σ\":%l,\n    \"Σµ\":%l,\n    \"m\":%l\n  }\n}\n";
static ngx_str_t stats_dest_name = {11, (u_char*)"/xtomp/stat"};

static void xtomp_destination_clean_messages(xtomp_core_dest_conf_t *dest);
static xtomp_message_t* xtomp_destination_stats(xtomp_core_dest_conf_t *dest, u_char * dest_name, ngx_uint_t size, ngx_uint_t q_size, ngx_uint_t delta, ngx_uint_t sum);
static xtomp_message_t* xtomp_destination_cc(void);

static ngx_uint_t uptime;

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





// TODO replace me with pointers

xtomp_core_dest_conf_t*
xtomp_destination_find(xtomp_core_srv_conf_t *cscf, ngx_str_t *dest_name)
{
    size_t                   i;
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

    if ( ( s->ws || s->web ) && dest->web_read_block_flag ) {
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
    xtomp_core_dest_conf_t  *stats_dest;
    xtomp_core_srv_conf_t   *cscf;
    xtomp_message_t         *m;
    ngx_int_t                rc;

    dest = log_evt->data;

    ngx_uint_t delta = dest->message_idx - dest->last_message_idx;
    dest->last_message_idx = dest->message_idx;

    cscf = dest->cscf;
    stats_dest = xtomp_destination_find(cscf, &stats_dest_name);
    if ( stats_dest ) {
        m = xtomp_destination_stats(dest, dest->name.data, dest->size, dest->q_size, delta, dest->message_idx);
        if ( m ) {
            //xtomp_destination_send(stats_dest, m);
            rc = xtomp_destination_put(stats_dest, m);
            if ( rc != NGX_OK ) {
                ngx_log_error(NGX_LOG_DEBUG, log_evt->log, 0, "xtomp pub stats failed");
            }
            xtomp_message_free(m);
        }
    }
    else {
        ngx_log_error(NGX_LOG_NOTICE, log_evt->log, 0, "xtomp d=%s s=%l, q=%l, Δ=%l, Σ=%l", dest->name.data, dest->size, dest->q_size, delta, dest->message_idx);
    }

// TODO is this necessary??
    if ( log_evt->timer_set ) {
        ngx_del_timer(log_evt);
    }
    ngx_add_timer(log_evt, XTOMP_STATS_INTERVAL);

}

static void
xtomp_destination_log_cc(ngx_event_t *log_evt)
{
    xtomp_core_dest_conf_t  *stats_dest;
    xtomp_core_srv_conf_t   *cscf;
    xtomp_message_t         *m;
    ngx_int_t                rc;

    cscf = xtomp_core_conf;
    stats_dest = xtomp_destination_find(cscf, &stats_dest_name);
    if ( stats_dest ) {
        m = xtomp_destination_cc();
        if ( m ) {
            rc = xtomp_destination_put(stats_dest, m);
            if ( rc != NGX_OK ) {
                ngx_log_error(NGX_LOG_DEBUG, log_evt->log, 0, "xtomp pub cc failed");
            }
            xtomp_message_free(m);
        }
    }
    else {

        ngx_log_error(NGX_LOG_NOTICE, log_evt->log, 0, "xtomp cc=%l Σ=%l", xtomp_count, xtomp_total);

    }

// TODO is this necessary??
    if ( log_evt->timer_set ) {
        ngx_del_timer(log_evt);
    }
    ngx_add_timer(log_evt, XTOMP_STATS_INTERVAL);

}
/**
 * Create statistics message
 */
static xtomp_message_t*
xtomp_destination_stats(xtomp_core_dest_conf_t *dest, u_char * dest_name, ngx_uint_t size, ngx_uint_t q_size, ngx_uint_t delta, ngx_uint_t sum)
{
    ngx_str_t        chunk;
    ngx_int_t        rc, len;
    u_char          *rv;
    xtomp_message_t *m;

    m = xtomp_message_create(NULL);
    if ( m == NULL ) {
        return NULL;
    }
    m->destination = &stats_dest_name;
    m->expiry = m->timestamp + XTOMP_STATS_INTERVAL / 1000;
    m->dest = 1;

    chunk.data = xtomp_calloc(1, XTOMP_STATS_MSG_SZ);
    if ( chunk.data == NULL ) {
        return NULL;
    }

    rv = ngx_snprintf(chunk.data, XTOMP_STATS_MSG_SZ, response_stats, dest_name, size, q_size, delta, sum);
    len = rv - chunk.data;
    if ( len == XTOMP_STATS_MSG_SZ ) {
        // truncated stats, not the end of the world
    }
    chunk.len = len;

    rc = xtomp_message_add_chunk(m, &chunk);
    xtomp_free(chunk.data);
    if ( rc != NGX_OK ) {
        xtomp_message_free(m);
        return NULL;
    }

    return m;
}


/**
 * Create cc message
 */
static xtomp_message_t*
xtomp_destination_cc(void)
{
    xtomp_core_dest_conf_t  *dest;
    xtomp_core_dest_conf_t **destinations;
    ngx_str_t        chunk;
    ngx_int_t        i, rc, len, mallocs, total_messages;
    u_char          *rv;
    xtomp_message_t *m;

    mallocs = 0;

    destinations = xtomp_core_conf->destinations;
    total_messages = 0;
    for ( i = 0 ; i < XTOMP_MAX_DESTINATIONS ; i++ ) {

        dest = destinations[i];
        if ( dest ) {
            total_messages += dest->message_idx;
        }
        else break;

    }

    m = xtomp_message_create(NULL);
    if ( m == NULL ) {
        return NULL;
    }
    m->destination = &stats_dest_name;
    m->expiry = m->timestamp + XTOMP_STATS_INTERVAL / 1000;
    m->dest = 1;

    chunk.data = xtomp_calloc(1, XTOMP_STATS_MSG_SZ);
    if ( chunk.data == NULL ) {
        return NULL;
    }

    rv = ngx_snprintf(chunk.data, XTOMP_STATS_MSG_SZ, response_cc, xtomp_count, uptime, xtomp_total, total_messages, mallocs);
    len = rv - chunk.data;
    if ( len == XTOMP_STATS_MSG_SZ ) {
        // truncated stats, not the end of the world
    }
    chunk.len = len;

    rc = xtomp_message_add_chunk(m, &chunk);
    xtomp_free(chunk.data);
    if ( rc != NGX_OK ) {
        xtomp_message_free(m);
        return NULL;
    }

    return m;
}

/**
 * Create a logger event timer that fires every 60 seconds
 */
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

    ngx_add_timer(log_evt, XTOMP_STATS_INTERVAL);
    log_evt->timer_set = 1;

    return NGX_OK;
}

ngx_int_t
xtomp_destination_logger_cc(ngx_log_t *log)
{
    ngx_event_t *log_evt = xtomp_perm_calloc(1, sizeof(ngx_event_t));
    if ( log_evt == NULL ) {
        return NGX_ERROR;
    }
    
    uptime = ngx_time();

    log_evt->data = "cc_evt";
    log_evt->handler = xtomp_destination_log_cc;
    log_evt->log = log;

    ngx_add_timer(log_evt, XTOMP_STATS_INTERVAL);
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

    if ( ( sess->ws || sess->web ) && dest->web_write_block_flag ) {
        return XTOMP_DESTINATION_BLOCKED;
    }

    return NGX_OK;
}














