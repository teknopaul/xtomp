/*
 * Contains code managing hash filters, to filter message to certain subscribers.
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>
#include "xtomp_hashmap.h"

// TODO this should all be in destination. or called xtomp_destination_filter.c



static ngx_str_t ngx_filter_str = { 6 , (u_char *)"filter" };

static inline ngx_table_elt_t *
xtomp_destination_copy_filter(ngx_table_elt_t *hdr)
{
    ngx_uint_t          i;
    u_char              ch, *p;
    ngx_table_elt_t    *hdr_new;
    u_char             *data_new;

    p = hdr->value.data;
    for ( i = 0 ; i < hdr->value.len ; i++ ) {
        ch = *p++;
        if ( ch == '=' ) {
            break;
        }
        // sanename.org validation
        if ( ch != '-' && (ch < 'a' || ch > 'z') ) {
            return NULL;
        }
    }
    if ( i == hdr->value.len ) {
        return NULL;
    }

    hdr_new = xtomp_calloc(1, sizeof(ngx_table_elt_t));
    if ( hdr_new == NULL ) {
        return NULL;
    }

    // name=value
    data_new = xtomp_malloc(hdr->value.len * sizeof(u_char));
    if ( data_new == NULL ) {
        xtomp_free(hdr_new);
        return NULL;
    }
    ngx_memcpy(data_new, hdr->value.data, hdr->value.len);


    hdr_new->key.data = data_new;
    hdr_new->key.len = i;
    hdr_new->value.data = data_new + i + 1;
    hdr_new->value.len = hdr->value.len - i - 1;

    return hdr_new;
}

xtomp_subscriber_t*
xtomp_destination_create_subscription(xtomp_core_dest_conf_t *dest, xtomp_session_t *sess, ngx_int_t id, ngx_uint_t ack)
{
    ngx_int_t           i;
    ngx_table_elt_t    *fltr;
    xtomp_subscriber_t *sub;

    sub = xtomp_calloc(1, sizeof(xtomp_subscriber_t));
    if ( sub == NULL ) {
        return NULL;
    }

    sub->dest = dest;
    sub->sess = sess;
    sub->id = id;
    sub->ack = ack;
    sub->timestamp = ngx_time();

    ngx_table_elt_t  *hdr;
    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        hdr =  sess->headers_in.user_def[i];
        if ( hdr ) {
            if ( xtomp_strcmp(&hdr->key, &ngx_filter_str) == 0 ) {
                fltr = xtomp_destination_copy_filter(hdr);
                if ( fltr == NULL ) {
                    xtomp_free(sub);
                    return NULL;
                }
                sub->filter = fltr;
                break;
            }
        }
    }

    return sub;
}

void
xtomp_destination_free_subscription(xtomp_subscriber_t *sub)
{
    if ( sub->filter ) {
        xtomp_free(sub->filter->key.data);
        xtomp_free(sub->filter);
    }
    xtomp_free(sub);
}

/* linked-list subscriptions - start */

ngx_int_t
xtomp_destination_subscribe_list(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub)
{
    xtomp_subscriber_t *prev;

    // Subscribe to the linked list
    if ( dest->size == 0 ) {
        dest->head = sub;
    }
    else {
        prev = dest->head;
        dest->head = sub;
        sub->next = prev;
        prev->prev = sub;
    }

    dest->size++;

    return NGX_OK;
}

ngx_int_t
xtomp_destination_unsubscribe_list(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub)
{

    if ( dest->head == sub ) {
        dest->head = sub->next;
        if (dest->head) dest->head->prev = NULL;
    }
    else {
        sub->prev->next = sub->next;
        if ( sub->next ) sub->next->prev = sub->prev;
    }

    dest->size--;

    return NGX_OK;
}

static ngx_int_t
xtomp_destination_send_list_internal(xtomp_subscriber_t *head, xtomp_core_dest_conf_t *dest, xtomp_message_t *m)
{
    xtomp_subscriber_t *sub, *tmp;
    xtomp_session_t    *sess;

    sub = head;

    while ( sub != NULL ) {

        if ( sub->sess ) {
            sess = sub->sess; // SIGSEV here, sub->sess->c must be NULLed when connections are closed (shudv b fixed?)
            xtomp_message_mq_push(sess, dest, sub->id, m);
        }
        sub = sub->next;

    }

    sub = head;

    while ( sub != NULL ) {

        tmp = sub;
        sub = sub->next;

        if ( tmp->sess ) {
            sess = tmp->sess;
            ngx_add_timer(sess->connection->write, 15000); // TODO configurable
            xtomp_send(sess->connection->write); // this can result in unsubscribe
        }

    }

    return NGX_OK;
}

ngx_int_t
xtomp_destination_send_list(xtomp_core_dest_conf_t *dest, xtomp_message_t *m)
{

    return xtomp_destination_send_list_internal(dest->head, dest, m);

}

/* linked-list subscriptions - end */

/* hashmap subscriptions - start */

ngx_int_t
xtomp_destination_subscribe_hash(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub)
{
    int                 rc;
    hashmap_t          *map;
    any_t               find;
    xtomp_subscriber_t *next, *tmp;

    map = dest->map;

    rc = hashmap_get(map, &sub->filter->value, &find);

    if (rc == MAP_MISSING) {
        hashmap_put(map, &sub->filter->value, sub);
    }
    else {
        // insert @ position 2 in the list (easier than updating the hashtable)
        next = find;
        tmp = next->next;
        next->next = sub;
        sub->prev = next;
        sub->next = tmp;
        if ( tmp ) tmp->prev = sub;
    }

    dest->size++;

    return NGX_OK;
}

ngx_int_t
xtomp_destination_unsubscribe_hash(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub)
{
    int                 rc;
    hashmap_t          *map;
    any_t               find;
    xtomp_subscriber_t *head;

    map = dest->map;

    rc = hashmap_get(map, &sub->filter->value, &find);

    if (rc == MAP_MISSING) {
        return NGX_ERROR;
    }
    else {
        head = find;

        // removing the head
        if ( head == sub ) {
            hashmap_remove(map, &sub->filter->value);
            if ( sub->next ) {
                head = sub->next;
                hashmap_put(map, &head->filter->value, head);
                head->prev = NULL;
            }
        }
        // unlink the sub from the chain
        else {
            sub->prev->next = sub->next;
            if ( sub->next ) sub->next->prev = sub->prev;
        }
        dest->size--;
    }

    return NGX_OK;

}

#ifdef XTOMP_SPAM_ON
static int
xtomp_destination_iterate_hash_push(void *m_in, void *sub_in)
{
    xtomp_message_t        *m;
    xtomp_session_t        *s;
    xtomp_subscriber_t     *sub, *next;
    xtomp_core_dest_conf_t *dest;

    m = m_in;
    sub = sub_in;
    next = sub;
    dest = sub->dest;

    while ( next != NULL ) {

        if ( next->c ) {
            s = next->c->data;
            xtomp_message_mq_push(s, dest, sub->id, m);
        }
        next = next->next;

    }

    return MAP_OK;
}
static int
xtomp_destination_iterate_hash_send(void *m_in, void *sub_in)
{
    xtomp_session_t    *sess;
    xtomp_subscriber_t *sub, *tmp;

    sub = sub_in;

    while ( sub != NULL ) {

        tmp = sub;
        sub = sub->next;
        if ( tmp->c ) {
            sess = tmp->c->data;
            ngx_add_timer(sess->connection->write, 15000); // TODO configurable
            xtomp_send(sess->connection->write);
        }

    }

    return MAP_OK;
}
#endif

ngx_int_t
xtomp_destination_send_hash(xtomp_core_dest_conf_t *dest, xtomp_message_t *m, ngx_str_t *key)
{
    hashmap_t          *map;
    any_t               find;
    xtomp_subscriber_t *sub;

#ifdef XTOMP_SPAM_ON
    if ( key = NULL ) {
        hashmap_iterate(map, xtomp_destination_iterate_hash_push, m);
        hashmap_iterate(map, xtomp_destination_iterate_hash_send, m);
        return NGX_OK;
    }
#endif

    map = dest->map;

    if ( hashmap_get(map, key, &find) == MAP_OK ) {
        sub = find;

        return xtomp_destination_send_list_internal(sub, dest, m);
    }
    else {
        if ( dest->no_subs_flag == 1 ) {
            xtomp_destination_nack(dest, m);

            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

/* hashmap subscriptions - end */





