/*
 * Generic hashmap manipulation functions
 * 
 * https://github.com/petewarden/c_hashmap
 *
 * Originally by Elliot C Back - http://elliottback.com/wp/hashmap-implementation-in-c/
 *
 * Modified by Pete Warden to fix a serious performance problem, support strings as keys
 * and removed thread synchronization - http://petewarden.typepad.com
 */
#ifndef _XTOMP_HASHMAP_INCLUDED_
#define _XTOMP_HASHMAP_INCLUDED_

#define MAP_MISSING -3  /* No such element */
#define MAP_FULL -2     /* Hashmap is full */
#define MAP_OMEM -1     /* Out of Memory */
#define MAP_OK 0        /* OK */

/*
 * any_t is a pointer.  This allows you to put arbitrary structures in
 * the hashmap.
 */
typedef void *any_t;

/*
 * PFany is a pointer to a function that can take two any_t arguments
 * and return an integer. Returns status code..
 */
typedef int (*PFany)(any_t, any_t);

/*
 * We need to keep keys and values 
 */
typedef struct {
    ngx_str_t  *key;
    ngx_int_t   in_use;
    any_t       data;
} hashmap_element;

typedef struct hashmap_s hashmap_t;

/*
 * A hashmap has some maximum size and current size,
 * as well as the data to hold.
 */
struct hashmap_s {
    ngx_int_t           table_size;
    ngx_int_t           size;
    hashmap_element    *data;
} ;


/*
 * Return an empty hashmap. Returns NULL if empty.
*/
hashmap_t* hashmap_new(void);

/*
 * Iteratively call f with argument (item, data) for
 * each element data in the hashmap. The function must
 * return a map status code. If it returns anything other
 * than MAP_OK the traversal is terminated. f must
 * not reenter any hashmap functions, or deadlock may arise.
 */
int hashmap_iterate(hashmap_t *map, PFany f, any_t item);

/*
 * Add an element to the hashmap. Return MAP_OK or MAP_OMEM.
 */
int hashmap_put(hashmap_t *map, ngx_str_t* key, any_t value);

/*
 * Get an element from the hashmap. Return MAP_OK or MAP_MISSING.
 */
int hashmap_get(hashmap_t *map, ngx_str_t* key, any_t *arg);

/*
 * Remove an element from the hashmap. Return MAP_OK or MAP_MISSING.
 */
int hashmap_remove(hashmap_t *map, ngx_str_t* key);

/*
 * Get any element. Return MAP_OK or MAP_MISSING.
 * remove - should the element be removed from the hashmap
 */
int hashmap_get_one(hashmap_t *map, any_t *arg, int remove);

/*
 * Free the hashmap
 */
void hashmap_free(hashmap_t *map);

/*
 * Get the current size of a hashmap
 */
int hashmap_length(hashmap_t *map);

#endif // _XTOMP_HASHMAP_INCLUDED_
