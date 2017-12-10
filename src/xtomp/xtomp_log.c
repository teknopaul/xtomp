
/*
 * Contains code for logging messages to disk
 * 
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>

static const char XTOMP_LOG_PERSIST_DIRECTORY[] = "/var/spool/xtomp/data/";



#define XTOMP_LOG_MSG_OVERHEAD      200
#define XTOMP_LOG_MSG_BUF_SZ        XTOMP_LOG_MSG_OVERHEAD + (XTOMP_MAX_HDRS * XTOMP_MAX_HDR_LEN)
#define XTOMP_LOG_MAX_EVENTS        1024
#define XTOMP_LOG_MAX_PATH          255


static const char message_headers[] = "message-id:%ui\ndestination:%V\ncontent-length:%ui\n";

typedef struct xtomp_log_file_ctx_s        xtomp_log_file_ctx_t;

struct xtomp_log_file_ctx_s {
    u_char                 *hostname;
    ngx_uint_t              port;
    u_char                 *path;
    ngx_int_t               offset;
    int                     fd;
    u_char                 *buffer;
    ngx_int_t               total_written;
    unsigned                die:1;
};

static xtomp_log_file_ctx_t *log_ctx;

static ngx_int_t
xtomp_log_write_headers(xtomp_message_t *m)
{
    size_t    len, hdr_len;
    u_char   *rv;
    u_char   *bufout;
    ngx_int_t rit;

    bufout =  log_ctx->buffer;

    rv = ngx_snprintf(bufout, XTOMP_LOG_MSG_BUF_SZ, message_headers, m->id, m->destination, m->length);
    len = rv - bufout;

    hdr_len = xtomp_headers_len(m->hdrs);

    xtomp_headers_user_def_print(bufout + len, m->hdrs);
    bufout[len + hdr_len] = '\n';

    len += + hdr_len + 1;

    rit = write(log_ctx->fd, bufout, len);
    if ( rit < 0 ) return NGX_ERROR;
    if ( rit == 0 ) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * Write message.
 *
 * @param m a defragged, \0 terminated message
 */
static ngx_int_t
xtomp_log_write_message(xtomp_message_t *m)
{

    ngx_int_t rit = write(log_ctx->fd, m->chunks[0].data[0]->data, m->chunks[0].data[0]->len);
    if ( rit < 0 ) {
        log_ctx->die = 1;
        return NGX_ERROR;
    }
    if ( rit == 0 ) {
        log_ctx->die = 1;
        return NGX_ERROR;
    }
    // terminate with "extra" \n as per xtomp-log spec
    rit = write(log_ctx->fd, "\n", 1);
    if ( rit != 1 ) {
        log_ctx->die = 1;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/**
 * Make pathname for storing messages
 */
static ngx_int_t
xtomp_log_mkpath(u_char *path)
{
    ngx_int_t dir_len = strlen(XTOMP_LOG_PERSIST_DIRECTORY);

    memcpy(path, XTOMP_LOG_PERSIST_DIRECTORY, dir_len);
    // TODO hostname + port
    memcpy(path + dir_len, "uber.stomp", strlen("uber.stomp") + 1);

    return NGX_OK;
}

/**
 * Rotate the log file when booting so we don't write to a file
 * that might be ended wtih only a partial written message.
 */
static ngx_int_t
xtomp_log_rotate_file(void)
{

    u_char *pos;
    u_char new_path[XTOMP_LOG_MAX_PATH];
    int     rc;

    // path + "." + new Date().getTime()
    pos = new_path;
    memcpy(pos, log_ctx->path, ngx_strlen(log_ctx->path));
    pos += ngx_strlen(log_ctx->path);
    *pos++ = '.';
    ngx_snprintf(pos, 20, "%i", ngx_time());

    rc = rename((const char*)log_ctx->path, (const char*)new_path);
    if ( rc == -1 ) {
        log_ctx->die = 1;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * Init files and memory (or leak memory and die).
 */
ngx_int_t
xtomp_log_init(xtomp_core_main_conf_t *cmcf)
{

    log_ctx = calloc(1, sizeof(xtomp_log_file_ctx_t));
    if ( log_ctx == NULL ) {
        return NGX_ERROR;
    }

    log_ctx->buffer = calloc(1, XTOMP_LOG_MSG_BUF_SZ);
    if ( log_ctx->buffer == NULL ) {
        log_ctx->die = 1;
        return NGX_ERROR;
    }

    log_ctx->path = calloc(1, 255);
    if ( log_ctx->path == NULL ) {
        log_ctx->die = 1;
        return NGX_ERROR;
    }
    xtomp_log_mkpath(log_ctx->path);

    // if the file exists rotate it
    struct stat statbuf;
    int rc = stat((const char *)log_ctx->path, &statbuf);
    if ( rc == -1 ) {
        if (errno != ENOENT) {
            return NGX_ERROR;
        }
    }
    else if ( statbuf.st_size > 0 ) {
        xtomp_log_rotate_file();
    }

    // TODO hostname & port, so we can haev N instances in one chroot.
    /* something like this
    ngx_array_t servers = cmcf->servers;
    xtomp_core_srv_conf_t *cscf = servers->elts;
    log_ctx->hostname = cscf->server_name;

    ngx_array_t listen = cmcf->listen;
    xtomp_listen_t *l = listen->elts;
    log_ctx->port = l->sockaddr-.port;
    */

    log_ctx->fd = open((const char*)log_ctx->path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if ( log_ctx->fd < 0 ) {
        log_ctx->die = 1;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * TODO 
 * This needs to be called before  xtomp_destination.c:xtomp_destination_send(dest, m_to);
 * We need the xtomp_session_t* to reply to, when its been fully stored (4 writes)
 * We need to know when session is terminated and not reference dangling pointers
 * We want this run in a a separate thread
 */
ngx_int_t
xtomp_log_store(xtomp_message_t *m)
{
    ngx_int_t   rc;

    if ( log_ctx->die ) return NGX_ERROR;

    rc = xtomp_log_write_headers(m);
    if ( rc != NGX_OK) {
        return rc;
    }

    rc = xtomp_log_write_message(m);
    if ( rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}



