/*
 * Contains code for managing memory outside of nginx pools because pool memory never free()d if the connection
 * is left open.
 *
 * Copyright (C) Teknopaul
 */

#include <ngx_core.h>




void*
xtomp_malloc(size_t size)
{
    return malloc(size); 
}

void*
xtomp_calloc(int count, size_t size)
{
    return calloc(count, size); 
}

void
xtomp_free(void *p)
{
    free(p);
}

/*
 * Permanent allocation that will never be free()d
 */
void*
xtomp_perm_calloc(int count, size_t size)
{
    return calloc(count, size); 
}
void*
xtomp_perm_malloc(size_t size)
{
    return malloc(size); 
}

ngx_int_t
xtomp_strcmp(ngx_str_t *s1, ngx_str_t *s2)
{
    if ( s1->len <= s2->len ) {
        return ngx_strncmp(s1->data, s2->data, s1->len);
    }
    else {
        return ngx_strncmp(s1->data, s2->data, s2->len);
    }
}

