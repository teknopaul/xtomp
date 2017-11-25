
/*
 * Parse HTTP Upgrade command and headers.
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



// non-destructive trim
static ngx_int_t
xtomp_ws_rtrim(ngx_str_t * key)
{
    ngx_int_t i;
    for ( i = key->len ; key->data[i] == ' ' ; i-- );
    return i;
}

/* 
 * Called when an HTTP header line has been parsed successfully
 */
static ngx_int_t
xtomp_ws_header_done(xtomp_session_t *s, ngx_uint_t header_hash)
{
    ngx_int_t               rc;
    ngx_table_elt_t        *h;
    xtomp_header_t         *hh;

    h = xtomp_calloc(1, sizeof(ngx_table_elt_t));
    if ( h == NULL ) {
        return XTOMP_INTERNAL_SERVER_ERROR;
    }

    h->hash = header_hash;

    h->key.len = s->header_name_end - s->header_name_start;
    h->key.data = s->header_name_start;

    h->value.len = s->header_end - s->header_start;
    h->value.data = s->header_start;

    xtomp_core_main_conf_t  *cmcf;
    cmcf = xtomp_get_module_main_conf(s, xtomp_core_module);


    hh = ngx_hash_find(&cmcf->headers_ws_in_hash, h->hash, h->key.data, xtomp_ws_rtrim(&h->key));

    ngx_log_debug2(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ws hdr: \"%V:%V\"", &h->key, &h->value);

    rc = NGX_OK;
    if ( hh ) {
        rc = hh->handler(s, h, hh->offset);
    }
    xtomp_free(h);

    return rc;
}

/**
 * Parse a HTTP Upgrade command which is in the format
 * 
 *  GET /whatever HTTP/1.1
 *  Host: server.example.com
 *  Upgrade: websocket
 *  Connection: Upgrade
 *  Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
 *  Sec-WebSocket-Protocol: stomp
 *  Sec-WebSocket-Version: 13
 *  Origin: http://example.com
 * 
 * Need to validate every field per the WebSockets spec
 */
ngx_int_t
xtomp_ws_parse_upgrade(xtomp_session_t *s)
{
    ngx_int_t   rc;
    u_char      ch, *p, *c;
    ngx_uint_t  hash,l;

    enum {
        sw_start = 0,
        sw_get,
        sw_get_lf,

        sw_hdr_start,
        sw_hdr_name,
        sw_hdr_value,
        sw_hdr_almost_done,

        sw_invalid,
        sw_almost_done

    } state;

    state = s->state;
    hash = s->header_hash;

    for ( p = s->buffer->pos; p < s->buffer->last; p++ ) {
        ch = *p;

        switch (state) {

        /* REQUEST command */
        case sw_start:

            s->cmd_start = p;
            state = sw_get;
            s->cmd.len = 0;
            s->command = XTOMP_PARSE_INVALID_COMMAND;

            /* fall through */

        case sw_get:

            c = s->cmd_start;

            l = p - c;
            if ( l == 0 ) {
                continue;
            }
            else if ( p - c == 1 ) {
                continue;
            }
            else if ( p - c == 2 ) {
                continue;
            }
            else if ( p - c == 3 ) {  //  GET

                if ( c[0] == 'G' && c[1] == 'E' && c[2] == 'T' ) {
                    s->command = STOMP_WS_GET;
                    state = sw_get_lf;
                    continue;
                }
                else {
                    return NGX_ERROR;
                }
            }

            else if ( p - c == 4 ) {
                ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp BUG passed a GET that is not");
            }

            if ( ch < 'A' || ch > 'z' ) {
                goto invalid;
            }
            continue;

        case sw_get_lf:
            switch (ch) {

            case CR:
                s->cmd.data = s->cmd_start;
                s->cmd.len = p - s->cmd_start;
                continue;

            case LF:
                if ( s->cmd.len == 0 ) {
                    s->cmd.data = s->cmd_start;
                    s->cmd.len = p - s->cmd_start;
                }
                // TODO could parse the whole GET line here if we cared.
                if ( s->cmd.len > 17 && ngx_strncmp("GET /health_check", s->cmd_start, 17) == 0 ) {
                    s->command = STOMP_WS_HEALTH;
                    return NGX_ERROR;
                }
                state = sw_hdr_start;
                continue;

            default:
                continue;
            }

        /* header first char */
        case sw_hdr_start:
            s->header_name_start = p;
            s->invalid_header = 0;

            switch (ch) {

            case CR:
                // two LF marks end of headers
                state = sw_almost_done;
                continue;

            case LF:
                // two LF marks end of headers
                goto done;

            default:
                if ( ch == ' ' ) {
                    continue;
                }
                state = sw_hdr_name;

                if ( ch == '\0' ) {
                    s->invalid_header = 1;
                    goto invalid;
                }
                if ( ch == ':' ) {
                    s->invalid_header = 1;
                    goto invalid;
                }

                *p = ngx_tolower(*p);
                hash = ngx_hash(0, ngx_tolower(ch));

                continue;

            }
            continue;

        /* header name */
        case sw_hdr_name:

            if ( (ch >= 'a' && ch <= 'z') || ch == '-' ) {
                hash = ngx_hash(hash, ch);
                continue;
            }
            else if ( ch >= 'A' && ch <= 'Z' ) {
                *p = ngx_tolower(*p);
                hash = ngx_hash(hash, ngx_tolower(ch));
                continue;
            }

            if ( ch == ':' ) {
                s->header_name_end = p;
                s->header_start = p + 1;
                state = sw_hdr_value;
                continue;
            }

            // TODO could bomb out on blank header values
            if ( ch == CR ) {
                s->header_name_end = p;
                s->header_start = p;
                s->header_end = p;
                state = sw_hdr_almost_done;
                continue;
            }

            if ( ch == LF ) {
                s->header_name_end = p;
                s->header_start = p;
                s->header_end = p;
                state = sw_hdr_start;
                continue;
            }

            // HTTP spec allows this xtomp does not
            s->invalid_header = 1;

            continue;

        /* header value */
        case sw_hdr_value:
            switch (ch) {

            case CR:
                s->header_end = p;
                state = sw_hdr_almost_done;
                continue;

            case LF:
                s->header_end = p;
                rc = xtomp_ws_header_done(s, hash);
                if ( rc ) {
                    return NGX_ERROR;
                }
                state = sw_hdr_start;
                continue;

            default:
                continue;
            }
            

        /* end of header line */
        case sw_hdr_almost_done:
            switch (ch) {

            case LF:
                rc = xtomp_ws_header_done(s, hash);
                if ( rc ) {
                    return NGX_ERROR;
                }
                state = sw_hdr_start;
                continue;

            case CR:
                continue;

            default:
                goto invalid;
            }
            continue;

        case sw_almost_done:
            switch (ch) {

            case CR:
            case LF:
                goto done;

            default:
                goto invalid;
            }

        case sw_invalid:
            goto invalid;

        default:
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp BUG unhandled swtich");
            goto invalid;

        } // end case

    } // end for

    s->buffer->pos = p;
    s->state = state;
    s->header_hash = hash;

    return NGX_AGAIN;

done:

    // ALL headers MUST be present and correct 
    if ( s->ws->hdr_upgrade &&
         s->ws->hdr_host &&
         s->ws->hdr_connection &&
         s->ws->hdr_protocol &&
         s->ws->hdr_version &&
         // not required per node JS WebSockets cleint
         // s->ws->hdr_origin &&
         s->ws->accept ) {

        s->ws->upgraded = 1;
        s->command = STOMP_COMMAND_UNKNOWN;
        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ws upgraded");

    } else {

        ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ws missing hdr");
        return NGX_ERROR;

    }

    s->buffer->pos = p + 1;
    s->state = 0;

    return NGX_OK;

invalid:

    s->state = sw_invalid;
    s->buffer->pos = p;

    return NGX_ERROR;
}


