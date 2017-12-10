
/*
 * Parse STOMP command and headers.
 * 
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



const char *STOMP_COMMANDS[] = {
    "init",         // STOMP_COMMAND_INIT          0
    "unknown",      // STOMP_COMMAND_UNKNOWN       1
    "ACK",          // STOMP_COMMAND_ACK           2
    "SEND",         // STOMP_COMMAND_SEND          3
    "NACK",         // STOMP_COMMAND_NACK          4
    "BEGIN",        // STOMP_COMMAND_BEGIN         5
    "ABORT",        // STOMP_COMMAND_ABORT         6
    "ERROR",        // STOMP_COMMAND_ERROR         7
    "COMMIT",       // STOMP_COMMAND_COMMIT        8
    "CONNECT",      // STOMP_COMMAND_CONNECT       9
    "MESSAGE",      // STOMP_COMMAND_MESSAGE       10
    "RECEIPIT",     // STOMP_COMMAND_RECEIPT       11
    "SUBSCRIBE",    // STOMP_COMMAND_SUBSCRIBE     12
    "CONNECTED",    // STOMP_COMMAND_CONNECTED     13
    "DISCONNECT",   // STOMP_COMMAND_DISCONNECT    14
    "UNSUBSCRIBE"   // STOMP_COMMAND_UNSUBSCRIBE   15
};

/* 
 * a header line has been parsed successfully
 */
static ngx_int_t
xtomp_request_header_done(xtomp_session_t *s, ngx_uint_t header_hash)
{
    ngx_int_t               rc;
    ngx_table_elt_t        *h;
    xtomp_header_t         *hh;

    // we don't deal with this at the moment, it should not be copied to client
    if ( ngx_strncmp(s->header_name_start, "session" , 7) == 0 ) {
        return NGX_OK;
    }

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

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash, h->key.data, h->key.len);

    ngx_log_debug2(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp header: \"%V:%V\"", &h->key, &h->value);

    if ( hh ) {
        rc = hh->handler(s, h, hh->offset);
    }
    else {
        rc = xtomp_headers_user_def_add(s, h);
    }


    return rc;
}

/**
 * Parse a STOMP command which is in the format
 * 
 *   COMMAND
 *   header1:value1
 *   header2:value2
 * 
 *   ^@
 * 
 * TODO Seems verbose, presumably Igor has worked out this is fast?
 */
ngx_int_t
xtomp_request_parse_command(xtomp_session_t *s)
{
    ngx_int_t   rc;
    u_char      ch, *p, *c, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10;
    ngx_uint_t  hash,l;

    enum {
        sw_start = 0,
        sw_command,
        sw_command_lf,

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

            // discard leading new lines
            if ( ch == '\n' || ch == '\r' ) {
                continue;
            }

            s->cmd_start = p;
            state = sw_command;
            s->cmd.len = 0;
            s->command = XTOMP_PARSE_INVALID_COMMAND;

            /* fall through */

        case sw_command:

            if ( ch == '*' ) {
                ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp BUG re-reading buffer");
            }
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
            else if ( p - c == 3 ) {  //  ACK, GET
                c0 = c[0];
                c1 = c[1];
                c2 = c[2];

                if ( c0 == 'A' && c1 == 'C' && c2 == 'K' ) {
                    s->command = STOMP_COMMAND_ACK;
                    goto comm_done;
                }
            }
            else if ( p - c == 4 ) {  //  NACK, SEND
                c0 = c[0];
                c1 = c[1];
                c2 = c[2];
                c3 = c[3];

                if ( c0 == 'N' && c1 == 'A' && c2 == 'C' && c3 == 'K' ) {
                    s->command = STOMP_COMMAND_NACK;
                    goto comm_done;
                }
                if ( c0 == 'S' && c1 == 'E' && c2 == 'N' && c3 == 'D' ) {
                    s->command = STOMP_COMMAND_SEND;
                    goto comm_done;
                }
            }
            else if ( p - c == 5 ) {  //  BEGIN, ABORT, ERROR, STOMP
                c0 = c[0];
                c1 = c[1];
                c2 = c[2];
                c3 = c[3];
                c4 = c[4];

                if ( c0 == 'S' && c1 == 'T' && c2 == 'O' && c3 == 'M' && c4 == 'P' ) {
                    s->command = STOMP_COMMAND_CONNECT;
                    goto comm_done;
                }
                else if ( c0 == 'B' && c1 == 'E' && c2 == 'G' && c3 == 'I' && c4 == 'N' ) {
                    s->command = STOMP_COMMAND_BEGIN;
                    goto comm_done;
                }
                else if ( c0 == 'A' && c1 == 'B' && c2 == 'O' && c3 == 'R' && c4 == 'T' ) {
                    s->command = STOMP_COMMAND_ABORT;
                    goto comm_done;
                }
                else if ( c0 == 'E' && c1 == 'R' && c2 == 'R' && c3 == 'O' && c4 == 'R' ) {
                    s->command = STOMP_COMMAND_ERROR;
                    goto comm_done;
                }
            }
            else if ( p - c == 6 ) {  //  COMMIT
                c0 = c[0];
                c1 = c[1];
                c2 = c[2];
                c3 = c[3];
                c4 = c[4];
                c5 = c[5];

                if ( c0 == 'C' && c1 == 'O' && c2 == 'M' && c3 == 'M' && c4 == 'I' && c5 == 'T' ) {
                    s->command = STOMP_COMMAND_COMMIT;
                    goto comm_done;
                }
            }
            else if ( p - c == 7 ) {  //  CONNECT, MESSAGE, RECEIPT
                c0 = c[0];
                c1 = c[1];
                c2 = c[2];
                c3 = c[3];
                c4 = c[4];
                c5 = c[5];
                c6 = c[6];

                if ( c0 == 'C' && c1 == 'O' && c2 == 'N' && c3 == 'N' && c4 == 'E' && c5 == 'C' && c6 == 'T' ) {
                    s->command = STOMP_COMMAND_CONNECT;
                    goto comm_done;
                }
                else if ( c0 == 'M' && c1 == 'E' && c2 == 'S' && c3 == 'S' && c4 == 'A' && c5 == 'G' && c6 == 'E' ) {
                    s->command = STOMP_COMMAND_MESSAGE;
                    goto comm_done;
                }
                else if ( c0 == 'R' && c1 == 'E' && c2 == 'C' && c3 == 'E' && c4 == 'I' && c5 == 'P' && c6 == 'T' ) {
                    s->command = STOMP_COMMAND_RECEIPT;
                    goto comm_done;
                }
            }
            else if ( p - c == 8 ) {
                continue;
            }
            else if ( p - c == 9 ) {  //  SUBSCRIBE, CONNECTED
                c0 = c[0];
                c1 = c[1];
                c2 = c[2];
                c3 = c[3];
                c4 = c[4];
                c5 = c[5];
                c6 = c[6];
                c7 = c[7];
                c8 = c[8];

                if ( c0 == 'S' && c1 == 'U' && c2 == 'B' && c3 == 'S' && c4 == 'C' && c5 == 'R' && c6 == 'I' && c7 == 'B' && c8 == 'E' ) {
                    s->command = STOMP_COMMAND_SUBSCRIBE;
                    goto comm_done;
                }
                else if ( c0 == 'C' && c1 == 'O' && c2 == 'N' && c3 == 'N' && c4 == 'E' && c5 == 'C' && c6 == 'T' && c7 == 'E' && c8 == 'D' ) {
                    s->command = STOMP_COMMAND_CONNECTED;
                    goto comm_done;
                }
            }
            else if ( p - c == 10 ) {  //  DISCONNECT
                c0 = c[0];
                c1 = c[1];
                c2 = c[2];
                c3 = c[3];
                c4 = c[4];
                c5 = c[5];
                c6 = c[6];
                c7 = c[7];
                c8 = c[8];
                c9 = c[9];

                if ( c0 == 'D' && c1 == 'I' && c2 == 'S' && c3 == 'C' && c4 == 'O' && c5 == 'N' && c6 == 'N' && c7 == 'E' && c8 == 'C' && c9 == 'T' ) {
                    s->command = STOMP_COMMAND_DISCONNECT;
                    goto comm_done;
                }
            }
            else if ( p - c == 11 ) {  //  UNSUBSCRIBE
                c0 = c[0];
                c1 = c[1];
                c2 = c[2];
                c3 = c[3];
                c4 = c[4];
                c5 = c[5];
                c6 = c[6];
                c7 = c[7];
                c8 = c[8];
                c9 = c[9];
                c10 = c[10];

                if ( c0 == 'U' && c1 == 'N' && c2 == 'S' && c3 == 'U' && c4 == 'B' && c5 == 'S' && c6 == 'C' && c7 == 'R' && c8 == 'I' && c9 == 'B' && c10 == 'E' ) {
                    s->command = STOMP_COMMAND_UNSUBSCRIBE;
                    goto comm_done;
                }
            }
            else if ( p - c == 12 ) {
                goto invalid;
            }


            if ( ch < 'A' || ch > 'z' ) {
                goto invalid;
            }
            continue;

        case sw_command_lf:
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
                state = sw_hdr_start;
                continue;

            default:
                goto invalid;
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
                if ( s->command == STOMP_COMMAND_SEND || s->command == STOMP_COMMAND_MESSAGE ) {
                    goto done;
                }
                state = sw_almost_done;
                continue;

            default:
                state = sw_hdr_name;

                if ( ch == '\0' ) {
                    s->invalid_header = 1;
                    goto invalid;
                }
                if ( ch == ':' ) {
                    s->invalid_header = 1;
                    goto invalid;
                }

                hash = ngx_hash(0, ch);
                continue;

            }
            continue;

        /* header name */
        case sw_hdr_name:

            if ( (ch >= 'a' && ch <= 'z') || ch == '-' || (ch >= 'A' && ch <= 'Z') ) {
                hash = ngx_hash(hash, ch);
                continue;
            }

            if ( ch == ':' ) {
                s->header_name_end = p;
                s->header_start = p + 1;
                state = sw_hdr_value;
                continue;
            }

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

            if ( ch == '\0' ) {
                goto invalid;
            }

            // STOMP spec allows this xtomp does not
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
                rc = xtomp_request_header_done(s, hash);
                if ( rc == XTOMP_HDR_FLUP ) {
                    return XTOMP_HDR_FLUP;
                }
                else if ( rc ) {
                    // TODO this is merging errors, inc malloc() fails which are not client errors
                    return XTOMP_PARSE_INVALID_COMMAND;
                }
                state = sw_hdr_start;
                continue;

            case '\0':
                goto invalid;

            default:
                continue;
            }

        /* end of header line */
        case sw_hdr_almost_done:
            switch (ch) {

            case LF:
                rc = xtomp_request_header_done(s, hash);
                if ( rc == XTOMP_HDR_FLUP ) {
                    return XTOMP_HDR_FLUP;
                }
                else if ( rc ) {
                    return XTOMP_PARSE_INVALID_COMMAND;
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
                if ( s->command == STOMP_COMMAND_SEND || s->command == STOMP_COMMAND_MESSAGE ) {
                    goto done;
                }
                continue;

            case 0:
                ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp end frame");
                goto done;

            default:
                goto invalid;
            }

        case sw_invalid:
            goto invalid;

        default:
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp BUG unhandled switch");
            goto invalid;

        } // end case

comm_done:

        ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp %s", STOMP_COMMANDS[s->command]);

        if (s->command == STOMP_COMMAND_DISCONNECT) {
            // nuf sed
            return NGX_OK;
        }

        switch(ch) {
        case '\r':
            state = sw_command_lf;
            continue;
        case '\n':
            state = sw_hdr_start;
            continue;
        case 'E':
            if ( s->command == STOMP_COMMAND_CONNECT ) continue;
        default : 
            return XTOMP_PARSE_INVALID_COMMAND;
        }

    } // end for

    s->buffer->pos = p;
    s->state = state;
    s->header_hash = hash;

    return NGX_AGAIN;

done:

    s->buffer->pos = p + 1;
    s->state = sw_start;

    return NGX_OK;

invalid:

    s->state = sw_invalid;
    s->buffer->pos = p;

    return XTOMP_PARSE_INVALID_COMMAND;
}

ngx_int_t
xtomp_request_parse_discard_frame(xtomp_session_t *s)
{
    u_char   *p;
    for ( p = s->buffer->pos; p < s->buffer->last; p++ ) {
        if ( *p == 0 ) {
            s->buffer->pos = p;
            s->state = 0;
            return NGX_OK;
        }
    }
    return NGX_AGAIN;
}

ngx_int_t
xtomp_request_parse_discard_newlines(xtomp_session_t *s)
{
    u_char   *p;
    for ( p = s->buffer->pos; p < s->buffer->last; p++ ) {
        if ( *p == '\r' || *p == '\n' ) {
            s->buffer->pos = p;
            continue;
        }
        break;
    }
    return NGX_OK;
}

