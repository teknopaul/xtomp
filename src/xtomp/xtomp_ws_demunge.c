
/*
 * Contains code for processing web sockets data streams.
 *
 * https://tools.ietf.org/html/rfc6455#section-5.5.2
 *
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>



/**
 * unmunge one frames worth of data, or all that is available now.
 * @return bytes unmunged.
 */
static ngx_int_t 
xtomp_ws_demunge_frame(xtomp_session_t *s, u_char *pos)
{
    // TODO XOR the data in 64bit chunks will probably be faster.
    u_char *p;
    u_char *masking_key = s->ws->masking_key;
    for ( p = pos; p < s->buffer->last && s->ws->frame_pos < s->ws->frame_len; p++, s->ws->frame_pos++ ) {
        *p = *p ^ masking_key[s->ws->frame_pos % 4];
    }

    // if we reached the end of a frame
    if ( s->ws->frame_pos == s->ws->frame_len ) {
        // if this is a FIN text frame
        if ( s->ws->opcode == 0x81 ) {
            // if we did process at least one char (so p-1 is valid)
            // and the end char of the ws frame is not '\0', i.e a valid STOMP frame
            // fail fast.
            if ( p != pos && *(p - 1) != '\0' ) {
                ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ws frame not message");
                return NGX_ERROR;
            }
        }
    }

    return p - pos;
}

static void
xtomp_ws_reset(xtomp_session_t *s)
{
    ngx_memset(s->ws, 0, sizeof(xtomp_ws_ctx_t));
}

static void
xtomp_ws_skip(xtomp_session_t *s, u_char *p, ngx_uint_t skip)
{
    ngx_memmove(p - skip, p, s->buffer->last - p);
    s->buffer->last -= skip;
    ngx_memset(s->buffer->last, 0 , skip);
}

/**
 * ws:// streams are delivered in annoying frames and the data stream is "masked" this is an XOR that
 * serves bugger all purpose other than to complicate things.
 * This code takes the buffer and unfucks it removing frame headers un xoring the data and removing additional
 * control frames.
 *
 * @param recv_start - This is the start point for demunging
 */
ngx_int_t
xtomp_ws_demunge(xtomp_session_t *s, u_char * recv_start)
{
    // flags to detect that one whole frame is delivered and nothing more
    u_char      *p, *init;
    u_char      ch, opcode;
    ngx_int_t   is_single_frame = 0;
    ngx_uint_t  skipped;
    ngx_int_t   processed;
    int64_t     tmp1, tmp2;

    enum {
        sw_start = 0,
        sw_payload_len_1,
        sw_payload_len_ext,
        sw_masking_key,
        sw_payload, // must be 4 in xtomp_request_body.c
        sw_payload_skip

    } state;

    state = s->ws->frame_state;
    skipped = 0;

    if ( s->buffer->pos == s->buffer->start ) is_single_frame++;

    init = recv_start ? recv_start : s->buffer->pos;
    for ( p = init; p < s->buffer->last; p++ ) {
        ch = *p;

        switch (state) {

        /* REQUEST command */
        case sw_start:

            xtomp_ws_reset(s);
            s->ws->opcode = ch;

            // FIN bit set
            if ( (ch & 0x80) == 0x80 ) is_single_frame++;
            state = sw_payload_len_1;

            skipped++;
            continue;

        case sw_payload_len_1:

            if ( (ch & 0x80) != 0x80 ) {
                // BUG client data must be masked

                return NGX_ERROR;
            }

            if ( (ch & 0x7f) == 126 ) {
                s->ws->frame_len_idx = 2;
                state = sw_payload_len_ext;
            }
            else if ( (ch & 0x7f) == 127 ) {
                s->ws->frame_len_idx = 8;
                state = sw_payload_len_ext;
            }
            else {
                s->ws->frame_len = (ngx_uint_t)(ch & 0x7f);
                state = sw_masking_key;
            }

            skipped++;
            continue;

        case sw_payload_len_ext:
            tmp1 = (uint64_t)(ch & 0xFF);
            tmp2 = tmp1 << (8 * --s->ws->frame_len_idx);
            s->ws->frame_len_data |= tmp2;

            if ( s->ws->frame_len_idx == 0 ) {
                if ( s->ws->frame_len_data < 0 || s->ws->frame_len_data > XTOMP_WS_MAX_FRAME_LEN) {
                    ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ws frame flup %z", s->ws->frame_len_data);
                    return NGX_ERROR;
                }
                s->ws->frame_len = (ngx_uint_t)s->ws->frame_len_data;
                state = sw_masking_key;
            }

            skipped++;
            continue;

        case sw_masking_key:

            s->ws->masking_key[s->ws->masking_key_len_idx++] = ch;

            if ( s->ws->masking_key_len_idx == 4 ) {
                state = sw_payload;
            }

            skipped++;
            continue;

        case sw_payload:

            if ( s->ws->frame_len > XTOMP_WS_MAX_FRAME_LEN ) {
                ngx_log_debug1(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp ws frame flup %z", s->ws->frame_len);
                return NGX_ERROR;
            }

            opcode = s->ws->opcode & 0x0f;
            if ( opcode == 0x08 ) {
                // connection close
                return NGX_ERROR;
            }
            if ( opcode == 0x02 ) {
                // binary not supported
                return NGX_ERROR;
            }

            processed = xtomp_ws_demunge_frame(s, p);
            if (processed == NGX_ERROR) {
                return NGX_ERROR;
            }

            if ( opcode == 0x09 || opcode == 0x0a ) {
                // per stackoverflow https://stackoverflow.com/questions/10585355/sending-websocket-ping-pong-frame-from-browser
                // clients dont send pings, so we dont write complicated code to handle them
                // however just in case, we will skip over them.
                ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp unhandled ws ping");
            }

            // any unsupported opcodes, skip over.
            if ( opcode > 0x02 ) {
                // shift buffer erasing ws junk
                xtomp_ws_skip(s, p + processed, skipped + processed);
                p = p - skipped - 1; // -1 because p++ in for loop
                skipped = 0;
                is_single_frame = 0;
                if ( s->ws->frame_pos == s->ws->frame_len ) {
                    state = sw_start;
                }
                else if ( s->ws->frame_pos < s->ws->frame_len ) {
                    state = sw_payload_skip;
                }
                else {
                    ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp BUG overread ws buf");
                    return NGX_ERROR;
                }
                continue;
            }

            if ( is_single_frame == 2 && s->buffer->last - s->buffer->pos - skipped == s->ws->frame_len ) {
                // optimize instead of compact, shift pos
                s->buffer->pos = p;
                s->ws->frame_state = sw_start;
                return NGX_OK;
            }
            else {
                // shift buffer erasing ws junk
                xtomp_ws_skip(s, p, skipped);
                p = p + processed - skipped - 1; // -1 because p++ in for loop
                skipped = 0;
                is_single_frame = 0;
                if ( s->ws->frame_pos == s->ws->frame_len ) state = sw_start;
            }

            continue;

        case sw_payload_skip:
            processed = xtomp_ws_demunge_frame(s, p);
            xtomp_ws_skip(s, p, processed);
            if ( s->ws->frame_pos == s->ws->frame_len ) {
                state = sw_start;
            }
            continue;
        default:
            // BUG?
            ngx_log_debug0(NGX_LOG_DEBUG_XTOMP, s->connection->log, 0, "xtomp BUG unhandled switch");
            return NGX_ERROR;
        }
    }

    s->ws->frame_state = state;

    if ( p == s->buffer->pos ) {
        // did not read anything but everything is OK
        return NGX_AGAIN;
    }

    return NGX_OK;

}

/**
 * Write a websockets frame header.
 * @param buf, space to write to, should be 10 bytes long.
 * @param message_len the length of the ws frame this header prefixes.
 * @param type frame type
 * @return the amount of bytes in the header, 2, 4 or 10.
 */
size_t
xtomp_ws_frame_hdr(u_char *buf, size_t message_len, xtomp_frame_type_e type)
{
    int i;

    if ( type == non_fin_text ) {
        buf[0] = (u_char)0x01; // non-FIN text
    }
    else if ( type == fin_cont ) {
        buf[0] = (u_char)0x80; // FIN + cont
    }
    else if ( type == non_fin_cont ) {
        buf[0] = (u_char)0x00; // non-FIN cont
    }
    else if ( type == fin_text ) {
        buf[0] = (u_char)0x81; // FIN text
    }

    if ( message_len < 126 ) {
        buf[1] = (u_char)message_len;
        return 2;
    }
    else if ( message_len <= 0xffff) {
        buf[1] = (u_char)0x7e;
        for ( i = 0 ; i < 2 ; i++) buf[2 + i] = (u_char)(message_len >> 8 * (1 - i) & 0xff);
        return 4;
    }
    else {
        buf[1] = (u_char)0x7f;
        for ( i = 0 ; i < 8 ; i++) buf[2 + i] = (u_char)(message_len >> 8 * (7 - i) & 0xff);
        return 10;
    }

}


