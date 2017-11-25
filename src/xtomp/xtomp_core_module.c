/*
 * Contains core xtomp{} module code, and code that sets up the server, listeners and destinations.
 * 
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Teknopaul
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>

static void *xtomp_core_create_main_conf(ngx_conf_t *cf);
static void *xtomp_core_create_srv_conf(ngx_conf_t *cf);
static void *xtomp_core_create_dest_conf(ngx_conf_t *cf);
static char *xtomp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static char *xtomp_core_merge_dest_conf(ngx_conf_t *cf, void *parent, void *child);
static char *xtomp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *xtomp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *xtomp_core_destination(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t xtomp_init_process(ngx_cycle_t *cycle);
static char *xtomp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_uint_t init_log;

static ngx_command_t  xtomp_core_commands[] = {

    { ngx_string("server"),
      XTOMP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      xtomp_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      XTOMP_SRV_CONF|NGX_CONF_1MORE,
      xtomp_core_listen,
      XTOMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("request_client_buffer"),
      XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, client_buffer_size),
      NULL },

    { ngx_string("response_client_buffer"),
      XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, client_bufout_size),
      NULL },

    { ngx_string("protocol"),
      XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, protocol_name),
      NULL },

    { ngx_string("login"),
      XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, login),
      NULL },

    { ngx_string("passcode"),
      XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, passcode),
      NULL },

    { ngx_string("secret"),
      XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, secret),
      NULL },

    { ngx_string("secret_timeout"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, secret_timeout),
      NULL },

    { ngx_string("websockets_origin"),
      XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, websockets_origin),
      NULL },

    { ngx_string("websockets"),
      XTOMP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, websockets),
      NULL },

    { ngx_string("destination"),
      XTOMP_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      xtomp_core_destination,
      XTOMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("name"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, name),
      NULL },

    { ngx_string("max_connections"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, max_connections),
      NULL },

    { ngx_string("max_message_size"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, max_message_size),
      NULL },

    { ngx_string("min_delivery"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, min_delivery),
      NULL },

    { ngx_string("max_messages"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, max_messages),
      NULL },

    { ngx_string("expiry"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, expiry),
      NULL },

    { ngx_string("filter"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, filter),
      NULL },

    { ngx_string("filter_header"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, filter_hdr),
      NULL },

    { ngx_string("stats"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, stats),
      NULL },

    { ngx_string("log_messages"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, log_messages),
      NULL },

    { ngx_string("no_subscribers"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, no_subs),
      NULL },

    { ngx_string("web_read_block"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, web_read_block),
      NULL },

    { ngx_string("web_write_block"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|XTOMP_DEST_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_slot,
      XTOMP_DEST_CONF_OFFSET,
      offsetof(xtomp_core_dest_conf_t, web_write_block),
      NULL },

    { ngx_string("timeout"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, timeout),
      NULL },

    { ngx_string("heart_beat_read"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, heart_beat_read),
      NULL },

    { ngx_string("heart_beat_write_min"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, heart_beat_write_min),
      NULL },

    { ngx_string("heart_beat_write_max"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, heart_beat_write_max),
      NULL },

    { ngx_string("server_name"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      XTOMP_SRV_CONF_OFFSET,
      offsetof(xtomp_core_srv_conf_t, server_name),
      NULL },

    { ngx_string("error_log"),
      XTOMP_MAIN_CONF|XTOMP_SRV_CONF|NGX_CONF_1MORE,
      xtomp_core_error_log,
      XTOMP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static xtomp_protocol_t  xtomp_default_protocol = {
    ngx_string("default"),
    { 61613, 0 },
    XTOMP_STOMP_PROTOCOL,

    xtomp_request_init_session,
    xtomp_request_init_protocol,
    xtomp_request_parse_command,

};

static xtomp_module_t  xtomp_core_module_ctx = {
    // TODO unused
    &xtomp_default_protocol,            /* protocol */

    xtomp_core_create_main_conf,        /* create main configuration */
    NULL,                               /* init main configuration */

    xtomp_core_create_srv_conf,         /* create server configuration */
    xtomp_core_merge_srv_conf,          /* merge server configuration */

    xtomp_core_create_dest_conf,        /* create destination configuration */
    xtomp_core_merge_dest_conf,         /* merge destination configuration */
};


ngx_module_t  xtomp_core_module = {
    NGX_MODULE_V1,
    &xtomp_core_module_ctx,             /* module context */
    xtomp_core_commands,                /* module directives */
    XTOMP_MODULE,                       /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    xtomp_init_process,                 /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static xtomp_core_srv_conf_t *xtomp_core_conf;

static void *
xtomp_core_create_main_conf(ngx_conf_t *cf)
{
    xtomp_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(xtomp_core_main_conf_t));
    if ( cmcf == NULL ) {
        return NULL;
    }

    if ( ngx_array_init(&cmcf->servers, cf->pool, 4, sizeof(xtomp_core_srv_conf_t *)) != NGX_OK ) {
        return NULL;
    }

    if ( ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(xtomp_listen_t)) != NGX_OK ) {
        return NULL;
    }

    if ( xtomp_init_headers_in_hash(cf, cmcf) != NGX_OK ) {
        return NULL;
    }

    if ( xtomp_init_headers_ws_in_hash(cf, cmcf) != NGX_OK ) {
        return NULL;
    }

    return cmcf;
}


static void *
xtomp_core_create_srv_conf(ngx_conf_t *cf)
{
    xtomp_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(xtomp_core_srv_conf_t));
    if ( cscf == NULL ) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->protocol = NULL;
     *     cscf->error_log = NULL;
     */
    cscf->protocol = &xtomp_default_protocol;

    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    cscf->secret_timeout = NGX_CONF_UNSET_MSEC;
    cscf->client_buffer_size = NGX_CONF_UNSET_SIZE;
    cscf->client_bufout_size = NGX_CONF_UNSET_SIZE;
    cscf->heart_beat_read = NGX_CONF_UNSET_MSEC;
    cscf->heart_beat_write_min = NGX_CONF_UNSET_MSEC;
    cscf->heart_beat_write_max = NGX_CONF_UNSET_MSEC;

    cscf->resolver = NGX_CONF_UNSET_PTR;
    cscf->websockets = NGX_CONF_UNSET_UINT;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    cscf->destination_count = 0;
    cscf->destinations = ngx_pcalloc(cf->pool, sizeof(void *) * XTOMP_MAX_DESTINATIONS);
    if ( cscf->destinations == NULL ) {
        return NULL;
    }

    return cscf;
}


static void *
xtomp_core_create_dest_conf(ngx_conf_t *cf)
{

    xtomp_core_dest_conf_t  *dest;

    dest = ngx_pcalloc(cf->pool, sizeof(xtomp_core_dest_conf_t));
    if ( dest == NULL ) {
        return NULL;
    }

    // dest->name.data = 0
    // dest->name.len = 0
    dest->size = 0;
    dest->max_connections = NGX_CONF_UNSET_UINT;
    dest->max_messages = NGX_CONF_UNSET_UINT;
    dest->max_message_size = NGX_CONF_UNSET_UINT;
    dest->min_delivery = NGX_CONF_UNSET_UINT;
    dest->expiry = NGX_CONF_UNSET_MSEC;
    dest->log = cf->log;

    return dest;
}


static char *
xtomp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    xtomp_core_srv_conf_t *prev = parent;
    xtomp_core_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->timeout,              prev->timeout,              120000);
    ngx_conf_merge_msec_value(conf->resolver_timeout,     prev->resolver_timeout,     30000);
    ngx_conf_merge_msec_value(conf->secret_timeout,       prev->secret_timeout,     60000);
    ngx_conf_merge_size_value(conf->client_buffer_size,   prev->client_buffer_size,   (size_t) ngx_pagesize);
    ngx_conf_merge_size_value(conf->client_bufout_size,   prev->client_bufout_size,   (size_t) XTOMP_BUFOUT_LEN);
    ngx_conf_merge_size_value(conf->heart_beat_read,      prev->heart_beat_read,      120000);
    ngx_conf_merge_size_value(conf->heart_beat_write_min, prev->heart_beat_write_min, 60000);
    ngx_conf_merge_size_value(conf->heart_beat_write_max, prev->heart_beat_write_max, 180000);


    ngx_conf_merge_str_value(conf->server_name,        prev->server_name,        "xtomp");
    ngx_conf_merge_str_value(conf->protocol_name,      prev->protocol_name,      "stomp");
    ngx_conf_merge_str_value(conf->login,              prev->login,              NULL);
    ngx_conf_merge_str_value(conf->passcode,           prev->passcode,           NULL);
    ngx_conf_merge_str_value(conf->secret,             prev->secret,             NULL);
    ngx_conf_merge_str_value(conf->websockets_origin,  prev->websockets_origin,  NULL);
    // TODO free prev, no? or are there none by default?
    ngx_conf_merge_ptr_value(conf->destinations,       prev->destinations,   NULL);

    if ( conf->server_name.len == 0 ) {
        conf->server_name = cf->cycle->hostname;
    }

    if ( conf->error_log == NULL ) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    ngx_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);

    // TODO default listen
    // TODO default destination
    if ( conf->secret.data != NULL && conf->secret.len < 12 ) {
        ngx_log_stderr(0, "[error]: crap password: %s", conf->secret.data);
    }

    xtomp_core_conf = conf;

    return NGX_CONF_OK;
}


static char *
xtomp_core_merge_dest_conf(ngx_conf_t *cf, void *parent, void *child)
{
    // TODO parent is wrong, need to understand what merge is about really

    //xtomp_core_dest_conf_t *prev = parent;
    xtomp_core_dest_conf_t *dest = child;

    if ( dest->name.data == NULL ) {
        ngx_str_set(&dest->name, "unknown");
    }
    if ( dest->max_connections  == NGX_CONF_UNSET_UINT ) dest->max_connections  = (ngx_uint_t)1000;
    if ( dest->max_messages     == NGX_CONF_UNSET_UINT ) dest->max_messages     = (ngx_uint_t)100;
    if ( dest->max_message_size == NGX_CONF_UNSET_UINT ) dest->max_message_size = (ngx_uint_t)XTOMP_MAX_MSG_LEN;
    if ( dest->min_delivery     == NGX_CONF_UNSET_UINT ) dest->min_delivery     = (ngx_uint_t)0;
    if ( dest->expiry           == NGX_CONF_UNSET_MSEC ) dest->expiry           = (ngx_msec_t)(1000 * 120);

    if ( dest->max_connections == 0 ) return NGX_CONF_ERROR;
    if ( dest->max_messages == 0 ) return NGX_CONF_ERROR;
    if ( dest->max_message_size == 0 ) return NGX_CONF_ERROR;

    dest->pool = ngx_create_pool(2048, cf->log);

    dest->queue = ngx_pcalloc(cf->pool, (size_t)(dest->max_messages * sizeof(xtomp_message_t*)));
    if ( dest->queue == NULL ) {
        return NGX_CONF_ERROR;
    }
    dest->log = &cf->cycle->new_log;

    if ( dest->filter.len && ngx_strcmp(dest->filter.data, "on") == 0 ) {
        dest->map = hashmap_new();
        if ( dest->map == NULL ) {
            return NGX_CONF_ERROR;
        }
        dest->filter_flag = 1;
    }
    if ( dest->filter.len && ngx_strcmp(dest->filter.data, "required") == 0 ) {
        dest->map = hashmap_new();
        if ( dest->map == NULL ) {
            return NGX_CONF_ERROR;
        }
        dest->filter_flag = 2;
    }

    if ( dest->min_delivery == 0 ) {
        dest->no_subs_flag = 1;
    }

    if ( dest->web_read_block.len && ngx_strcmp(dest->web_read_block.data, "on") == 0 ) {
        dest->web_read_block_flag = 1;
    }
    if ( dest->web_write_block.len && ngx_strcmp(dest->web_write_block.data, "on") == 0 ) {
        dest->web_write_block_flag = 1;
    }
    if ( dest->log_messages.len && ngx_strcmp(dest->log_messages.data, "on") == 0 ) {
        init_log++;
        dest->log_messages_flag = 1;
    }
    /* TODO memq
    if ( dest->no_subs.len ) {
        if ( ngx_strcmp(dest->no_subs.data, "buffer") == 0 ) dest->no_subs_flag = 0;
        if ( ngx_strcmp(dest->no_subs.data, "drop") == 0 )   dest->no_subs_flag = 1;
    }
    */


    return NGX_CONF_OK;
}

static char *
xtomp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                    *rv;
    void                    *mconf;
    ngx_uint_t               m;
    ngx_conf_t               pcf;
    xtomp_module_t          *module;
    xtomp_conf_ctx_t        *ctx, *xtomp_ctx;
    xtomp_core_srv_conf_t   *cscf, **cscfp;
    xtomp_core_main_conf_t  *cmcf;

    init_log = 0;

    ctx = ngx_pcalloc(cf->pool, sizeof(xtomp_conf_ctx_t));
    if ( ctx == NULL ) {
        return NGX_CONF_ERROR;
    }

    xtomp_ctx = cf->ctx;
    ctx->main_conf = xtomp_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * xtomp_max_module);
    if ( ctx->srv_conf == NULL ) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if ( cf->cycle->modules[m]->type != XTOMP_MODULE ) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if ( module->create_srv_conf ) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[xtomp_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[xtomp_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if ( cscfp == NULL ) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;

    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = XTOMP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    if ( rv == NGX_CONF_OK && !cscf->listen ) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no \"listen\" is defined for server in %s:%ui",
                      cscf->file_name, cscf->line);
        return NGX_CONF_ERROR;
    }

    if ( init_log ) {
        ngx_int_t irc = xtomp_log_init(cmcf);
        if (irc != NGX_OK) return NGX_CONF_ERROR;
    }

    return rv;
}


static char *
xtomp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xtomp_core_srv_conf_t   *cscf = conf;

    ngx_str_t               *value;
    ngx_url_t                u;
    ngx_uint_t               i;
    xtomp_listen_t          *ls;
    xtomp_core_main_conf_t  *cmcf;

    cscf->listen = 1;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if ( ngx_parse_url(cf->pool, &u) != NGX_OK ) {
        if ( u.err ) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = xtomp_conf_get_module_main_conf(cf, xtomp_core_module);

    ls = cmcf->listen.elts;

    for ( i = 0; i < cmcf->listen.nelts; i++ ) {

        if ( ngx_cmp_sockaddr(&ls[i].sockaddr.sockaddr, ls[i].socklen,
                             (struct sockaddr *) &u.sockaddr.sockaddr, u.socklen, 1)  != NGX_OK ) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    ls = ngx_array_push(&cmcf->listen);
    if ( ls == NULL ) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(xtomp_listen_t));

    ngx_memcpy(&ls->sockaddr.sockaddr, &u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->backlog = NGX_LISTEN_BACKLOG;
    ls->wildcard = u.wildcard;
    ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    for ( i = 2; i < cf->args->nelts; i++ ) {

        if ( ngx_strcmp(value[i].data, "bind") == 0 ) {
            ls->bind = 1;
            continue;
        }

        if ( ngx_strncmp(value[i].data, "backlog=", 8) == 0 ) {
            ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if ( ls->backlog == NGX_ERROR || ls->backlog == 0 ) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if ( ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0 ) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            size_t  len;
            u_char  buf[NGX_SOCKADDR_STRLEN];

            if ( ls->sockaddr.sockaddr.sa_family == AF_INET6 ) {

                if ( ngx_strcmp(&value[i].data[10], "n") == 0 ) {
                    ls->ipv6only = 1;

                } else if ( ngx_strcmp(&value[i].data[10], "ff") == 0 ) {
                    ls->ipv6only = 0;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
                len = ngx_sock_ntop(&ls->sockaddr.sockaddr, ls->socklen, buf,
                                    NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if ( ngx_strcmp(value[i].data, "ssl") == 0 ) {
#if (XTOMP_SSL)
            ls->ssl = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "xtomp_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        if ( ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0 ) {

            if (ngx_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;

            } else if ( ngx_strcmp(&value[i].data[13], "off") == 0 ) {
                ls->so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if ( p == NULL ) {
                    p = end;
                }

                if ( p > s.data ) {
                    s.len = p - s.data;

                    ls->tcp_keepidle = ngx_parse_time(&s, 1);
                    if ( ls->tcp_keepidle == (time_t) NGX_ERROR ) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if ( p == NULL ) {
                    p = end;
                }

                if ( p > s.data ) {
                    s.len = p - s.data;

                    ls->tcp_keepintvl = ngx_parse_time(&s, 1);
                    if ( ls->tcp_keepintvl == (time_t) NGX_ERROR ) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if ( s.data < end ) {
                    s.len = end - s.data;

                    ls->tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if ( ls->tcp_keepcnt == NGX_ERROR ) {
                        goto invalid_so_keepalive;
                    }
                }

                if ( ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0 && ls->tcp_keepcnt == 0 ) {
                    goto invalid_so_keepalive;
                }

                ls->so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            ls->bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
xtomp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xtomp_core_srv_conf_t  *cscf = conf;

    return ngx_log_set_log(cf, &cscf->error_log);
}

static char *
xtomp_core_destination(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    char                    *rv;
    ngx_uint_t               i;
    ngx_conf_t               save;

    xtomp_module_t          *module;
    xtomp_conf_ctx_t        *ctx, *pctx;
    xtomp_core_dest_conf_t  *cdcf;
    xtomp_core_srv_conf_t   *cscf;

    ctx = ngx_pcalloc(cf->pool, sizeof(xtomp_conf_ctx_t));
    if ( ctx == NULL ) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->dest_conf = ngx_pcalloc(cf->pool, sizeof(void *) * xtomp_max_module);
    if ( ctx->dest_conf == NULL ) {
        return NGX_CONF_ERROR;
    }

    for ( i = 0; cf->cycle->modules[i]; i++ ) {
        if (cf->cycle->modules[i]->type != XTOMP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if ( module->create_dest_conf ) {
            ctx->dest_conf[cf->cycle->modules[i]->ctx_index] = module->create_dest_conf(cf);
            if ( ctx->dest_conf[cf->cycle->modules[i]->ctx_index] == NULL ) {
                return NGX_CONF_ERROR;
            }
        }
    }

    cdcf = ctx->dest_conf[xtomp_core_module.ctx_index];
    cdcf->dest_conf = ctx->dest_conf;

    /* parse inside destination{} */

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = XTOMP_DEST_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    // from here we have dest conf data

    for ( i = 0; cf->cycle->modules[i]; i++ ) {
        if ( cf->cycle->modules[i]->type != XTOMP_MODULE ) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if ( module->merge_dest_conf ) {
            module->merge_dest_conf(cf, cdcf, cdcf);
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_XTOMP, cf->log, 0, "Created destination: %s:%u", cdcf->name.data,  cdcf->max_connections);

    cscf = conf;
    cscf->destinations[cscf->destination_count++] = cdcf;

    return rv;
}

static ngx_int_t
xtomp_init_process(ngx_cycle_t *cycle)
{

    ngx_uint_t                i;
    xtomp_core_srv_conf_t    *cscf;
    xtomp_core_dest_conf_t   *dest;

    cscf = xtomp_core_conf; // Only support one stomp{} block

    for ( i = 0 ; i < cscf->destination_count ; i++ ) {

        dest = cscf->destinations[i];

        if ( dest != NULL && dest->stats.len && ngx_strcmp(dest->stats.data, "on") == 0 ) {
            xtomp_destination_logger(dest);
        }
    }

    return NGX_OK;
}
