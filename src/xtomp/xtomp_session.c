
/*
 * Contains code for managing a session's subscriptions.
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



ngx_int_t
xtomp_session_subs_add(xtomp_session_t *sess, xtomp_subscriber_t *sub)
{
    ngx_uint_t     i;

    if (sess->subs_size == XTOMP_MAX_SUBS) return XTOMP_SUBS_FLUP;

    for (i = 0 ; i < XTOMP_MAX_SUBS ; i++) {
        if ( sess->subs[i] == NULL ) {
            sess->subs[i] = sub;
            break;
        }
    }
    sess->subs_size++;

    return NGX_OK;
}

ngx_int_t
xtomp_session_subs_remove(xtomp_session_t *sess, xtomp_subscriber_t *sub)
{
    ngx_uint_t     i;

    for (i = 0 ; i < XTOMP_MAX_SUBS ; i++) {
        if ( sess->subs[i] == sub ) {
            sess->subs[i] = NULL;
            break;
        }
    }
    sess->subs_size--;

    return NGX_OK;
}

void
xtomp_session_close(xtomp_session_t *sess)
{
    ngx_uint_t              i;

    for (i = 0 ; i < XTOMP_MAX_SUBS ; i++) {
        if ( sess->subs[i] != NULL ) {
            xtomp_destination_unsubscribe(sess->subs[i]);
            sess->subs[i] = NULL;
        }
    }
    sess->subs_size = 0;
}

xtomp_subscriber_t *
xtomp_session_subs_find(xtomp_session_t *sess, ngx_str_t *dest_name, ngx_int_t id)
{
    ngx_uint_t              i;
    xtomp_subscriber_t *sub;

    for (i = 0 ; i < XTOMP_MAX_SUBS ; i++) {
        sub = sess->subs[i];
        if ( sub != NULL ) {
            if ( sub->id == id && 
                xtomp_strcmp(dest_name, &sub->dest->name) == 0 ) {
                return sub;
            }
        }
    }
    return NULL;
}


