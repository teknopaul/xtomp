
/*
 * Contains code for acting on STOMP messages.
 * 
 * TODO rename to xtomp_command_handler.c
 * 
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Teknopaul
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_sha1.h>
#include <xtomp.h>
#include <xtomp.h>
#include <openssl/sha.h>



#define STOMP_AUTH_USE_256 0

static ngx_int_t xtomp_auth_sha1cmp(ngx_str_t login, ngx_str_t passcode, ngx_str_t secret, ngx_uint_t secret_timeout);
static ngx_int_t xtomp_auth_sha256cmp(ngx_str_t login, ngx_str_t passcode, ngx_str_t secret, ngx_uint_t secret_timeout);
static ngx_int_t xtomp_auth_timeout(ngx_str_t login, ngx_uint_t secret_timeout);

/**
 * auth with username & password
 *
 * @return NGX_OK if login required and OK or login not set in xtomp.conf 
 */
ngx_int_t
xtomp_auth_login_passcode(xtomp_session_t *sess, ngx_connection_t *c)
{
    xtomp_core_srv_conf_t  *sscf;
    sscf = xtomp_get_module_srv_conf(sess, xtomp_core_module);

    if ( sscf->login.data != NULL ) {

        if ( sess->headers_in.login == NULL ||
             sess->headers_in.passcode == NULL ||
             sscf->login.len != sess->headers_in.login->value.len ||
             sscf->passcode.len != sess->headers_in.passcode->value.len ||
             ngx_strncmp(sess->headers_in.login->value.data,    sscf->login.data,    sscf->login.len) != 0 ||
             ngx_strncmp(sess->headers_in.passcode->value.data, sscf->passcode.data, sscf->passcode.len) != 0
        ) {
            return NGX_ERROR;
        }
        else {
            return NGX_OK;
        }
    }
    return NGX_OK;
}

/**
 * auth with hash based on a shared secret  hash(login + secret)
 *
 * @return NGX_OK if login secret required and OK, or secret not set in xtomp.conf
 */
ngx_int_t
xtomp_auth_sha(xtomp_session_t *sess, ngx_connection_t *c)
{
    xtomp_core_srv_conf_t  *sscf;
    sscf = xtomp_get_module_srv_conf(sess, xtomp_core_module);

    if ( sscf->secret.data != NULL ) {

        if ( sess->headers_in.login == NULL || sess->headers_in.passcode == NULL) return NGX_ERROR;

        if (STOMP_AUTH_USE_256) {
            return xtomp_auth_sha256cmp(sess->headers_in.login->value, sess->headers_in.passcode->value, sscf->secret, sscf->secret_timeout / 1000);
        } else {
            return xtomp_auth_sha1cmp(sess->headers_in.login->value, sess->headers_in.passcode->value, sscf->secret, sscf->secret_timeout / 1000);
        }

    }
    return NGX_OK;
}

/*
 * copy the username to the session, and zero terminate, 
 * the username is the characters up to the first space or the full string if there are no spaces.
 */
ngx_int_t
xtomp_auth_set_login_name(xtomp_session_t *sess, ngx_connection_t *c)
{
    ngx_table_elt_t    *h;
    size_t              len;

    h = sess->headers_in.login;

    if ( h != NULL ) {

        len = 0;
        while (h->value.data[len] != (u_char)' ' && len < h->value.len) len++;

        sess->login.data = ngx_pcalloc(sess->connection->pool, sizeof(u_char) + len + 1);
        if ( sess->login.data == NULL ) {
            return NGX_ERROR;
        }
        ngx_memcpy(sess->login.data, h->value.data, len);
        sess->login.len = len;
        sess->login.data[len] = 0;

    }

    return NGX_OK;
}

/**
 * @param secret_timeout in seconds
 */
static ngx_int_t
xtomp_auth_sha1cmp(ngx_str_t login, ngx_str_t passcode, ngx_str_t secret, ngx_uint_t secret_timeout)
{
    // SHA1 hash input
    u_char hash[20];
    ngx_sha1_t ctx;
    size_t out_len;

    ngx_sha1_init(&ctx);
    ngx_sha1_update(&ctx, login.data, login.len);
    ngx_sha1_update(&ctx, secret.data, secret.len);
    ngx_sha1_final(hash, &ctx);

    // base64 the result (data needs to be freed)
    u_char* result = xtomp_base64(hash, 20, &out_len);
    if (result == NULL) {
        return NGX_ERROR;
    }
    // rtrim \n
    while (result[out_len - 1] == (u_char)'\n') out_len--;

    //printf("%s,%s\n", result, passcode.data);
    if (out_len == passcode.len && ngx_strncmp(result, passcode.data, out_len) == 0) {
        xtomp_free(result);
        return xtomp_auth_timeout(login, secret_timeout);
    }
    else {
        xtomp_free(result);
        return NGX_ERROR;
    }
}

static ngx_int_t
xtomp_auth_sha256cmp(ngx_str_t login, ngx_str_t passcode, ngx_str_t secret, ngx_uint_t secret_timeout)
{

    u_char hash[32];
    SHA256_CTX sha256;
    size_t out_len;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, login.data,  login.len);
    SHA256_Update(&sha256, secret.data, secret.len);
    SHA256_Final(hash, &sha256);

    // base64 the result (data needs to be freed)
    u_char* result = xtomp_base64(hash, 32, &out_len);
    if (result == NULL) {
        return NGX_ERROR;
    }
    // rtrim \n
    while (result[out_len - 1] == (u_char)'\n') out_len--;

    //printf("%s,%s\n", result, passcode.data);
    if (out_len == passcode.len && ngx_strncmp(result, passcode.data, out_len) == 0) {
        xtomp_free(result);
        return xtomp_auth_timeout(login, secret_timeout);
    }
    else {
        xtomp_free(result);
        return NGX_ERROR;
    }

}

/**
 * Check that the login has not timed out, login must be   login + ' ' + timestamp + ' ' + random
 * @param secret_timeout in seconds
 */
static ngx_int_t
xtomp_auth_timeout(ngx_str_t login, ngx_uint_t secret_timeout)
{
    ngx_uint_t    i;
    ngx_int_t     timestamp;
    u_char       *pos, *start, *end;
    time_t        now;

    // login.split(' ')[1]
    start = 0, end = 0;
    pos = login.data;
    for ( i = 0 ; i < login.len ; i++ ) {
        if ( *pos++ == (u_char)' ') {
            if ( start == 0 ) {
                start = pos;
            }
            else {
                end = pos - 1;
                break;
            }
        }
    }
    if ( start && i == login.len ) end = pos;

    if ( start && end ) {
        now = ngx_time();
        timestamp = ngx_atoi(start, end - start);
        if ( timestamp == NGX_ERROR ) return NGX_ERROR;

        // should not happen if computer's dates are in sync
        if (now < (time_t)timestamp) return NGX_OK;

        if ( (now - (time_t)timestamp) < (time_t)secret_timeout) return NGX_OK;

        return NGX_DECLINED;

    }

    return NGX_ERROR;
}


