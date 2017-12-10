
/*
 * Contains code for heart-beats
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



static u_char *heart_beat = (u_char *)"\n";
static const char *heart_beat_header = "heart-beat:%ui,%ui\n";

ngx_int_t
xtomp_ecg_connect(xtomp_session_t *s)
{
    ngx_int_t               cpos;
    ngx_uint_t              cx,cy;
    u_char                 *comma;
    xtomp_core_srv_conf_t  *sscf;

    sscf = xtomp_get_module_srv_conf(s, xtomp_core_module);

    if ( s->headers_in.heart_beat != NULL ) {
        comma = (u_char *)memchr(s->headers_in.heart_beat->value.data, ',', s->headers_in.heart_beat->value.len);
        if ( comma == NULL ) {
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ecg syntax");
            return NGX_ERROR;
        }
        cpos = comma - s->headers_in.heart_beat->value.data;

        cx = (ngx_uint_t)ngx_atoi(s->headers_in.heart_beat->value.data, cpos);
        cy = (ngx_uint_t)ngx_atoi(++comma, s->headers_in.heart_beat->value.len - cpos - 1);
        if ( cx == 0 ) {
            s->heart_beat_read = 0;
        }
        else if ( cx > sscf->heart_beat_read ) {
            // error client can only guarantee beats every cx but we need beats every sscf->heart_beat_read
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ecg incompat");
            return NGX_ERROR;
        }
        else {
            s->heart_beat_read = sscf->heart_beat_read;
        }

        if ( cy == 0 || sscf->heart_beat_write_max == 0 ) {
            s->heart_beat_write = 0;
        }
        else if ( cy < sscf->heart_beat_write_min ) {
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ecg incompat");
            return NGX_ERROR;
        }
        else if ( cy > sscf->heart_beat_write_max ) {
            s->heart_beat_write = sscf->heart_beat_write_max;
        }
        else {
            s->heart_beat_write = cy;
        }

    }
    else {
        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ecg defaults");
        s->heart_beat_read = sscf->heart_beat_read;
        s->heart_beat_write = sscf->heart_beat_write_max;
    }

    return NGX_OK;
}

/*
 * Set read timeout to the interval we expect the client to ping
 * us at + a healthy margin for the network to deliver the packet.
 */
void
xtomp_ecg_set_read_timeout(xtomp_session_t *s, ngx_event_t *rev)
{
    if ( rev->timer_set ) {
        ngx_del_timer(rev);
    }

    if ( s->heart_beat_read ) {
        ngx_add_timer(rev, s->heart_beat_read + 15000);
    }
    else {
        xtomp_core_srv_conf_t  *sscf;
        sscf = xtomp_get_module_srv_conf(s, xtomp_core_module);
        ngx_add_timer(rev, sscf->timeout);
    }
}

/*
 * STOMP spec says the client should give us a margin for the network too, so send on the button.
 */
void
xtomp_ecg_set_write_timeout(xtomp_session_t *s, ngx_event_t *wev)
{
    if ( wev->timer_set ) {
        ngx_del_timer(wev);
    }

    if ( s->heart_beat_write ) {
        ngx_add_timer(wev, s->heart_beat_write);
    }
    else {
        xtomp_core_srv_conf_t  *sscf;
        sscf = xtomp_get_module_srv_conf(s, xtomp_core_module);
        ngx_add_timer(wev, sscf->timeout);
    }
}

ngx_int_t
xtomp_ecg_write_header(xtomp_session_t *s, u_char *bufout, ngx_int_t pos)
{
    u_char  *rc;
    xtomp_core_srv_conf_t  *sscf;

    sscf = xtomp_get_module_srv_conf(s, xtomp_core_module);

    rc = ngx_snprintf(bufout + pos, sscf->client_bufout_size - pos, heart_beat_header, s->heart_beat_write, s->heart_beat_read);

    return rc - bufout - pos;
}

/*
 * Presumes the timeout that not really a failure to write, just an indication that its
 * time to ping the client to keep the TCP connection open.
 * TODO make that distinction more clear, editing nginx core evt code?
 */
ngx_int_t
xtomp_ecg_handle_write_timeout(ngx_event_t *wev)
{
    ngx_connection_t       *c;
    xtomp_session_t        *s;

    c = wev->data;
    s = c->data;

    if ( s->heart_beat_write == 0 ) {
        return NGX_ERROR;
    }

    if ( s->xtomp_state == xtomp_conn_subscribed || s->xtomp_state == xtomp_conn_connected ) {

        if ( s->out.len == 0 ) {

            s->out.data = heart_beat;
            s->out.len = 1;
            wev->timedout = 0;
            xtomp_send(wev);

            return NGX_OK;
        }
        return NGX_ERROR;

    }
    return NGX_ERROR;
}


