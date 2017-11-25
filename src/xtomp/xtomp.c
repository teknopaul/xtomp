
/*
 * Contains code for the outer xtomp {} block in the configuration file.
 * 
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <xtomp.h>


static char *xtomp_init_conf(ngx_cycle_t *cycle, void *conf);
static char *xtomp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t xtomp_add_ports(ngx_conf_t *cf, ngx_array_t *ports, xtomp_listen_t *listen);
static char *xtomp_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);
static ngx_int_t xtomp_add_addrs(ngx_conf_t *cf, xtomp_port_t *mport, xtomp_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t xtomp_add_addrs6(ngx_conf_t *cf, xtomp_port_t *mport, xtomp_conf_addr_t *addr);
#endif
static ngx_int_t xtomp_cmp_conf_addrs(const void *one, const void *two);


ngx_uint_t  xtomp_max_module;


static ngx_command_t  xtomp_commands[] = {

    { ngx_string("xtomp"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      xtomp_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  xtomp_module_ctx = {
    ngx_string("xtomp"),
    NULL,
    xtomp_init_conf
};


ngx_module_t  xtomp_module = {
    NGX_MODULE_V1,
    &xtomp_module_ctx,                     /* module context */
    xtomp_commands,                        /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * Called after everything else has loaded from the config file.
 */
static char *
xtomp_init_conf(ngx_cycle_t *cycle, void *conf)

{
    return NGX_CONF_OK;
}

static char *
xtomp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *rv;
    ngx_uint_t                i, m, mi, s;
    ngx_conf_t                pcf;
    ngx_array_t               ports;
    xtomp_listen_t           *listen;
    xtomp_module_t           *module;
    xtomp_conf_ctx_t         *ctx;
    xtomp_core_srv_conf_t   **cscfp;
    xtomp_core_main_conf_t   *cmcf;

    if (*(xtomp_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main xtomp context */

    ctx = ngx_pcalloc(cf->pool, sizeof(xtomp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(xtomp_conf_ctx_t **) conf = ctx;

    /* count the number of the xtomp modules and set up their indices */

    xtomp_max_module = ngx_count_modules(cf->cycle, XTOMP_MODULE);


    /* the xtomp main_conf context, it is the same in the all xtomp contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool, sizeof(void *) * xtomp_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the xtomp null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * xtomp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's and the null srv_conf's of the all xtomp modules
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != XTOMP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

    }


    /* parse inside the xtomp{} block */

    pcf = *cf;
    cf->ctx = ctx;

    cf->module_type = XTOMP_MODULE;
    cf->cmd_type = XTOMP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init xtomp{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[xtomp_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != XTOMP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init xtomp{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }

            }
        }
    }

    *cf = pcf;


    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(xtomp_conf_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    listen = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (xtomp_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return xtomp_optimize_servers(cf, &ports);
}


static ngx_int_t
xtomp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    xtomp_listen_t *listen)
{
    in_port_t           p;
    ngx_uint_t          i;
    struct sockaddr    *sa;
    xtomp_conf_port_t  *port;
    xtomp_conf_addr_t  *addr;

    sa = &listen->sockaddr.sockaddr;
    p = ngx_inet_get_port(sa);

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {
        if (p == port[i].port && sa->sa_family == port[i].family) {

            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;

    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(xtomp_conf_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

found:

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->opt = *listen;

    return NGX_OK;
}

/*
 * Contains the main hook to core NGINX code ngx_create_listening()
 * that hooks up the xtomp module with nginx connection handling.
 * Also defines socket options.
 */
static char *
xtomp_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{
    ngx_uint_t              i, p, last, bind_wildcard;
    ngx_listening_t        *ls;
    xtomp_port_t           *mport;
    xtomp_conf_port_t      *port;
    xtomp_conf_addr_t      *addr;
    xtomp_core_srv_conf_t  *cscf;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(xtomp_conf_addr_t), xtomp_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (addr[last - 1].opt.wildcard) {
            addr[last - 1].opt.bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {

            if (bind_wildcard && !addr[i].opt.bind) {
                i++;
                continue;
            }

            ls = ngx_create_listening(cf, &addr[i].opt.sockaddr.sockaddr,
                                      addr[i].opt.socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = xtomp_init_connection;
            ls->pool_size = 256;

            cscf = addr->opt.ctx->srv_conf[xtomp_core_module.ctx_index];

            ls->logp = cscf->error_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

            ls->backlog = addr[i].opt.backlog;

            ls->keepalive = addr[i].opt.so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].opt.tcp_keepidle;
            ls->keepintvl = addr[i].opt.tcp_keepintvl;
            ls->keepcnt = addr[i].opt.tcp_keepcnt;
#endif

#if (NGX_HAVE_INET6)
            ls->ipv6only = addr[i].opt.ipv6only;
#endif

            mport = ngx_palloc(cf->pool, sizeof(xtomp_port_t));
            if (mport == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = mport;

            mport->naddrs = i + 1;

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                if (xtomp_add_addrs6(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (xtomp_add_addrs(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            addr++;
            last--;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
xtomp_add_addrs(ngx_conf_t *cf, xtomp_port_t *mport,
    xtomp_conf_addr_t *addr)
{
    u_char              *p;
    size_t               len;
    ngx_uint_t           i;
    xtomp_in_addr_t     *addrs;
    struct sockaddr_in  *sin;
    u_char               buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool, mport->naddrs * sizeof(xtomp_in_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin = &addr[i].opt.sockaddr.sockaddr_in;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].opt.ctx;

        len = ngx_sock_ntop(&addr[i].opt.sockaddr.sockaddr, addr[i].opt.socklen,
                            buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
xtomp_add_addrs6(ngx_conf_t *cf, xtomp_port_t *mport,
    xtomp_conf_addr_t *addr)
{
    u_char               *p;
    size_t                len;
    ngx_uint_t            i;
    xtomp_in6_addr_t     *addrs6;
    struct sockaddr_in6  *sin6;
    u_char                buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool, mport->naddrs * sizeof(xtomp_in6_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin6 = &addr[i].opt.sockaddr.sockaddr_in6;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].opt.ctx;

        len = ngx_sock_ntop(&addr[i].opt.sockaddr.sockaddr, addr[i].opt.socklen,
                            buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs6[i].conf.addr_text.len = len;
        addrs6[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}

#endif


static ngx_int_t
xtomp_cmp_conf_addrs(const void *one, const void *two)
{
    const xtomp_conf_addr_t  *first, *second;

    first = (const xtomp_conf_addr_t *) one;
    second = (const xtomp_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}


ngx_int_t
xtomp_init_headers_in_hash(ngx_conf_t *cf, xtomp_core_main_conf_t *cmcf)
{
    ngx_array_t         headers_in;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    xtomp_header_t     *header;

    if ( ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t)) != NGX_OK ) {
        return NGX_ERROR;
    }

    for (header = xtomp_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &cmcf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}



// WEBSOCKETS:

ngx_int_t
xtomp_init_headers_ws_in_hash(ngx_conf_t *cf, xtomp_core_main_conf_t *cmcf)
{
    ngx_array_t         headers_in;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    xtomp_header_t     *header;

    if ( ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t)) != NGX_OK ) {
        return NGX_ERROR;
    }

    for (header = xtomp_ws_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &cmcf->headers_ws_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "headers_ws_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

