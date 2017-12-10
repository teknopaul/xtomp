/*
 * Contains code managing incomming messages.
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



xtomp_message_t *
xtomp_message_create(xtomp_core_dest_conf_t *dest)
{
    xtomp_message_t        *m;
    xtomp_message_chunk_t  *chunk;

    m = xtomp_calloc(1, sizeof(xtomp_message_t));
    if ( m == NULL ) {
        return NULL;
    }
    chunk = xtomp_calloc(1, sizeof(xtomp_message_chunk_t));
    if ( chunk == NULL ) {
        xtomp_free(m);
        return NULL;
    }

    m->timestamp = ngx_time();
    m->id = 0;
    // dest is NULL for server generated messages
    if ( dest ) {
        m->destination = &dest->name;
        m->expiry = m->timestamp + dest->expiry / 1000;
    }
    m->chunks = chunk;
    m->defragged = 0;
    m->sent = 0;
    m->constant = 0;
    chunk->pos = -1;

    return m;
}

static void xtomp_message_free_chunk(xtomp_message_chunk_t *chunk);

// N.B. this is needed only when ./compile prod is used (-03)
#pragma GCC diagnostic ignored "-Wstrict-overflow"
static void
xtomp_message_free_chunk(xtomp_message_chunk_t *chunk)
{
    ngx_int_t     i;

    if ( chunk->next != NULL ) { // TODO SIGSEV here?
        xtomp_message_free_chunk(chunk->next);
    }

    for ( i = chunk->pos ; i >= 0 ; i-- ) {
        xtomp_free(chunk->data[i]->data);
        xtomp_free(chunk->data[i]);
    }
    xtomp_free(chunk);
}

#pragma GCC diagnostic ignored "-Wstrict-overflow"
void
xtomp_message_free(xtomp_message_t *m)
{
    ngx_int_t   i;

    if ( m->constant == 0 ) {
        xtomp_message_free_chunk(m->chunks);
    } else {
        xtomp_free(m->chunks);
    }


    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        if ( m->hdrs[i] != NULL ) {
            xtomp_free(m->hdrs[i]->key.data);
            xtomp_free(m->hdrs[i]);
        }
        else break;
    }

    xtomp_free(m);
}

ngx_int_t
xtomp_message_add_chunk(xtomp_message_t *m, ngx_str_t *chunk)
{
    xtomp_message_chunk_t      *c;
    ngx_str_t                  *new_string;
    u_char                     *new_data;

    if ( chunk->len == 0 ) return NGX_OK;

    c = m->chunks;

    while ( c->next != NULL ) c = c->next;

    if ( c->pos == XTOMP_MESSAGE_CHUNKS - 1 ) {
        c->next = xtomp_calloc(1, sizeof(xtomp_message_chunk_t));
        if ( c->next == NULL ) {
            return NGX_ERROR;
        }
        c->next->pos = -1;

        c = c->next;
    }

    // Create new space and copy data so it can live on the queue
    new_string = xtomp_calloc(1, sizeof(ngx_str_t));
    if ( new_string == NULL ) {
        return NGX_ERROR;
    }
    new_data = xtomp_malloc(sizeof(u_char) * (chunk->len + 1));
    if ( new_data == NULL ) {
        xtomp_free(new_string);
        return NGX_ERROR;
    }
    new_string->data = new_data;

    ngx_memcpy(new_string->data, chunk->data, chunk->len);
    new_string->data[chunk->len] = 0;
    new_string->len = chunk->len;

    c->pos++;
    c->data[c->pos] = new_string;
    m->length += chunk->len;

    return NGX_OK;
}

static void
xtomp_message_defrag_chunk(xtomp_message_chunk_t  *c, u_char *new_data)
{
    ngx_int_t    i;

    for ( i = 0 ; i <= c->pos ; i++ ) {
        if ( c->data[i] ) {
            ngx_memcpy(new_data, c->data[i]->data, c->data[i]->len);
            new_data += c->data[i]->len;
        }
    }
    if ( c->next ) {
        xtomp_message_defrag_chunk(c->next, new_data);
    }
}

/*
 * Takes a message that has been received in chunks
 * Copies it to a single message chunk
 * Zero terminates it
 * After defrag message can not be edited because str.len and content_length no longer equate
 * if returns NGX_ERROR message has not been altered
 */
#pragma GCC diagnostic ignored "-Wstrict-overflow"
ngx_int_t
xtomp_message_defrag(xtomp_message_t *m_to, xtomp_message_t *m_from)
{

    ngx_str_t                  *new_string;
    u_char                     *new_data;

    new_string = xtomp_calloc(1, sizeof(ngx_str_t));
    if ( new_string == NULL ) {
        return NGX_ERROR;
    }

    new_data = xtomp_malloc(sizeof(u_char) * (m_from->length + 1));
    if ( new_data == NULL ) {
        xtomp_free(new_string);
        return NGX_ERROR;
    }

    xtomp_message_defrag_chunk(m_from->chunks, new_data);

    new_string->data = new_data;
    new_string->len = m_from->length + 1;
    new_string->data[new_string->len - 1] = '\0';

    m_to->id = m_from->id;
    m_to->destination = m_from->destination;
    m_to->timestamp = m_from->timestamp;
    m_to->expiry = m_from->expiry;
    m_to->length = m_from->length;
    m_to->chunks->data[0] = new_string;
    m_to->chunks->pos = 0;
    m_to->chunks->next = NULL;
    m_to->defragged = 1;

    return NGX_OK;
}

ngx_str_t *
xtomp_message_get_header(xtomp_message_t *m, ngx_str_t *name)
{
    ngx_int_t   i;

    for ( i = 0 ; i < XTOMP_MAX_HDRS ; i++ ) {
        if ( m->hdrs[i] != NULL ) {
            if ( xtomp_strcmp(name, &m->hdrs[i]->key) == 0 ) {
                return &m->hdrs[i]->value;
            }
        }
        else break;
    }

    return NULL;
}
// mq handling 

xtomp_mq_t*
xtomp_message_mq_push(xtomp_session_t *s, xtomp_core_dest_conf_t *dest, ngx_uint_t sub_id, xtomp_message_t *m)
{
    xtomp_mq_t  *mq, *mq_new;

    mq_new = xtomp_calloc(1, sizeof(xtomp_mq_t));
    if ( mq_new == NULL ) {
        return NULL;
    }

    mq_new->message = m;
    mq_new->dest = dest;
    mq_new->sub_id = sub_id;

    if ( s->mq_size == 0 ) {
        s->mq = mq_new;
    }
    else {
        mq = s->mq;
        while ( mq->next != NULL ) mq = mq->next;
        mq->next = mq_new;
    }
    s->mq_size++;
    m->refs++;

    return mq_new;
}

xtomp_message_t *
xtomp_message_mq_pop(xtomp_session_t *s)
{
    xtomp_mq_t      *mq;
    xtomp_message_t *m;

    if ( s->mq_size == 0 ) return NULL;

    mq = s->mq;
    s->mq = mq->next;
    s->mq_size--;

    m = mq->message;
    m->refs--;
    xtomp_free(mq);

    return m;
}

xtomp_message_t *
xtomp_message_mq_remove(xtomp_session_t *s, ngx_uint_t id)
{
    xtomp_mq_t      *mq, *prev;
    xtomp_message_t *m;

    if ( s->mq_size == 0 ) return NULL;

    prev = NULL;
    mq = s->mq;
    while ( mq != NULL ) {
        if ( mq->message->id == id ) {
            m = mq->message;

            if ( prev ) prev->next = mq->next;
            else s->mq = mq->next;

            xtomp_free(mq);
            s->mq_size--;
            m->refs--;

            return m;
        }
        prev = mq;
        mq = mq->next;
    }

    return NULL;
}

xtomp_mq_t *
xtomp_message_mq_find(xtomp_session_t *s, ngx_uint_t id)
{
    xtomp_mq_t      *mq;

    mq = s->mq;
    while ( mq != NULL ) {
        if ( mq->message->id == id ) {
            return mq;
        }
        mq = mq->next;
    }

    return NULL;
}




