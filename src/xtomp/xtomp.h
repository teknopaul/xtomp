
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Teknopaul
 */


#ifndef _XTOMP_H_INCLUDED_
#define _XTOMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <xtomp_hashmap.h>



// commands (sync with stomp_parse.c)
#define STOMP_COMMAND_INIT          0  // Before any commands have been parsed
#define STOMP_COMMAND_UNKNOWN       1
#define STOMP_COMMAND_ACK           2
#define STOMP_COMMAND_SEND          3
#define STOMP_COMMAND_NACK          4
#define STOMP_COMMAND_BEGIN         5
#define STOMP_COMMAND_ABORT         6
#define STOMP_COMMAND_ERROR         7
#define STOMP_COMMAND_COMMIT        8
#define STOMP_COMMAND_CONNECT       9
#define STOMP_COMMAND_MESSAGE       10
#define STOMP_COMMAND_RECEIPT       11
#define STOMP_COMMAND_SUBSCRIBE     12
#define STOMP_COMMAND_CONNECTED     13
#define STOMP_COMMAND_DISCONNECT    14
#define STOMP_COMMAND_UNSUBSCRIBE   15

#define STOMP_WS_GET    16 // not really STOMP protocol
#define STOMP_WS_HEALTH 17 

// error codes

#define XTOMP_PARSE_INVALID_COMMAND  30
#define XTOMP_PARSE_INVALID_HEADER   31
// STOMP does not distinguish between client and server errors but we should
#define XTOMP_INTERNAL_SERVER_ERROR  32
#define XTOMP_BAD_REQUEST            33
#define XTOMP_DESTINATION_UNKNOWN    34
#define XTOMP_DESTINATION_FLUP       35
#define XTOMP_SUBSCRIPTION_UNKNOWN   36
#define XTOMP_Q_FLUP                 37
#define XTOMP_SUBS_FLUP              38
#define XTOMP_HDR_FLUP               39
#define XTOMP_DESTINATION_BLOCKED    40

// For now the only protocol, 1.2
#define XTOMP_STOMP_PROTOCOL  0
// change this and change the hardcoded strings in xtomp_response.c and version file
#define XTOMP_VERSION_MAJOR   0
#define XTOMP_VERSION_MINOR   2


// trusted port for admin type stuff
#define XTOMP_TRUSTED_PORT              61616

// Limits
#define XTOMP_LC_HEADER_LEN             32
// TODO anoying fixed size array but I cant get ngx_list to work!!
#define XTOMP_MAX_DESTINATIONS          100
#define XTOMP_MESSAGE_CHUNKS            32
#define XTOMP_BUFOUT_LEN                200
#define XTOMP_MAX_SUBS                  4
#define XTOMP_MAX_HDRS                  5
#define XTOMP_MAX_HDR_LEN               200      // fits sanename:sha512 
#define XTOMP_MAX_MSG_LEN               1048576  // 1 Mb
#define XTOMP_WS_MAX_FRAME_LEN          1048576  // 1 Mb


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
    void                  **dest_conf;
} xtomp_conf_ctx_t;


typedef struct {
    ngx_sockaddr_t          sockaddr;
    socklen_t               socklen;

    /* server ctx */
    xtomp_conf_ctx_t       *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
    unsigned                ssl:1;
#if (NGX_HAVE_INET6)
    unsigned                ipv6only:1;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
    int                     backlog;
} xtomp_listen_t;


typedef struct {
    xtomp_conf_ctx_t   *ctx;
    ngx_str_t           addr_text;
} xtomp_addr_conf_t;

typedef struct {
    in_addr_t           addr;
    xtomp_addr_conf_t   conf;
} xtomp_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr     addr6;
    xtomp_addr_conf_t   conf;
} xtomp_in6_addr_t;

#endif


typedef struct {
    /* xtomp_in_addr_t or xtomp_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} xtomp_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of xtomp_conf_addr_t */
} xtomp_conf_port_t;


typedef struct {
    xtomp_listen_t       opt;
} xtomp_conf_addr_t;


typedef struct {
    ngx_array_t             servers;       /* xtomp_core_srv_conf_t */
    ngx_array_t             listen;        /* xtomp_listen_t */

    ngx_hash_t              headers_in_hash;     /* STOMP header handlers */
    ngx_hash_t              headers_ws_in_hash;  /* HTTP WebSocket header handlers */
} xtomp_core_main_conf_t;


typedef struct xtomp_protocol_s        xtomp_protocol_t;
typedef struct xtomp_core_dest_conf_s  xtomp_core_dest_conf_t;
typedef struct xtomp_subscriber_s      xtomp_subscriber_t;
typedef struct xtomp_message_s         xtomp_message_t;
typedef struct xtomp_message_chunk_s   xtomp_message_chunk_t;
typedef struct xtomp_mq_s              xtomp_mq_t;
typedef struct xtomp_headers_in_s      xtomp_headers_in_t;
typedef struct xtomp_ws_ctx_s          xtomp_ws_ctx_t;

typedef struct {
    xtomp_protocol_t       *protocol;
    ngx_str_t               protocol_name;
    ngx_str_t               login;
    ngx_str_t               secret;
    ngx_str_t               passcode;
    ngx_flag_t              websockets;
    ngx_str_t               websockets_origin;

    ngx_msec_t              timeout;
    ngx_msec_t              resolver_timeout;
    ngx_msec_t              secret_timeout;
    size_t                  client_buffer_size;
    size_t                  client_bufout_size;
    ngx_str_t               server_name;
    ngx_msec_t              heart_beat_read;
    ngx_msec_t              heart_beat_write_min;
    ngx_msec_t              heart_beat_write_max;

    u_char                 *file_name;
    ngx_uint_t              line;

    ngx_resolver_t         *resolver;
    ngx_log_t              *error_log;

    /* server ctx */
    xtomp_conf_ctx_t       *ctx;

    ngx_uint_t              listen;        /* unsigned  listen:1; */
    ngx_uint_t              session_count;
    ngx_uint_t              destination_count;

    xtomp_core_dest_conf_t **destinations;

} xtomp_core_srv_conf_t;

// filter_flag
typedef enum {

    xtomp_filter_off = 0,
    xtomp_filter_on

} xtomp_filter_flag_e;

struct xtomp_core_dest_conf_s {
    xtomp_core_srv_conf_t  *cscf;         // core server config towhich this destination belongs
    ngx_str_t               name;
    ngx_uint_t              max_connections;
    ngx_uint_t              max_messages;     // max undelivered messages
    ngx_uint_t              max_message_size; // max size of uploaded message body
    ngx_uint_t              min_delivery;     // min times a message must be delivered to consider it sent, 0 disables holding on to messages for-redelivery
    ngx_msec_t              expiry;       // timediff in millis
    ngx_str_t               filter;       // filter messages on topics based on headers
    ngx_str_t               filter_hdr;   // name of the header used for filtering
    ngx_str_t               no_subs;      // what to when a message arrives and there are no subscribers
    ngx_str_t               stats;        // whether to debug log destination size
    ngx_str_t               web_write_block;       // whether to debug log destination size
    ngx_str_t               web_read_block;        // whether to debug log destination size
    void                  **dest_conf;
    ngx_str_t               log_messages;

    ngx_pool_t             *pool;  // memory pool forhte destination
    ngx_log_t              *log;   // logger

    xtomp_subscriber_t     *head;  // head of linked list
    hashmap_t              *map;
    ngx_uint_t              size;  // number of connections

    xtomp_message_t       **queue; // ring buffer of message pointers
    ngx_uint_t              q_head;
    ngx_uint_t              q_tail;
    ngx_uint_t              q_size;
    ngx_uint_t              message_idx;      // sued as msg counter 
    ngx_uint_t              last_message_idx; // per minute

    unsigned                filter_flag:2;   // 0 off, 1 on
    unsigned                no_subs_flag:2;  // 0 buffer, 1 drop, TODO block
    unsigned                web_write_block_flag:1; // prevent SEND from websockets
    unsigned                web_read_block_flag:1; // prevent SUBSCRIBE from websockets
    unsigned                log_messages_flag:1;
};


// xtomp_state
typedef enum {
    xtomp_conn_start = 0, // not received a singel read event yet
    xtomp_conn_initial,   // reading initial data
    xtomp_conn_connected,
    xtomp_conn_subscribed,
    xtomp_conn_disconnected,
    xtomp_conn_errored

} xtomp_conn_state_e;


struct xtomp_headers_in_s {

    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *ack;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *login;
    ngx_table_elt_t                  *passcode;
    ngx_table_elt_t                  *receipt;
    ngx_table_elt_t                  *heart_beat;
    ngx_table_elt_t                  *id;

    ngx_table_elt_t                  *user_def[XTOMP_MAX_HDRS];
};


//  mq state
typedef enum {
    xtomp_mq_new = 0,
    xtomp_mq_send_hdrs,
    xtomp_mq_sent_hdrs,
    xtomp_mq_send_body,
    xtomp_mq_sent_body,
    xtomp_mq_sent,
    xtomp_mq_ack,
    xtomp_mq_nack,

} xtomp_mq_state_e;

/*
 * q of message for a single connection
 */
struct xtomp_mq_s {
    xtomp_message_t         *message;
    ngx_uint_t               sub_id; // subscription id
    xtomp_core_dest_conf_t  *dest;
    xtomp_mq_t              *next;
    ngx_uint_t               state;
};


struct xtomp_ws_ctx_s {
    // frame parsing
    ngx_uint_t              frame_state;
    ngx_uint_t              frame_pos;
    ngx_uint_t              masking_key_len_idx;
    ngx_uint_t              frame_len_idx;   // counter for 1, 2 or 8 byte
    int64_t                 frame_len_data;  // MUST be 64bits for we parsing to work value is always < XTOMP_WS_MAX_FRAME_LENGTH
    ngx_uint_t              frame_len;
    u_char                  opcode;
    u_char                  masking_key[4];
    u_char                  hdr_buf[10];     // buffer for preparing ws frame header data
    ngx_uint_t              hdr_write_len;   // length of buffer written

    u_char                 *accept;          // base64 accept header response (xtomp_malloced)
    unsigned                hdr_upgrade:1;   // flags indicating given header was provided
    unsigned                hdr_host:1;
    unsigned                hdr_connection:1;
    unsigned                hdr_protocol:1;
    unsigned                hdr_version:1;
    unsigned                hdr_origin:1;
    unsigned                upgraded:1;      // upgrade received
    unsigned                upgrade_sent:1;  // upgrade response sent

};


typedef struct {
    xtomp_headers_in_t      headers_in;    // Headers received from client
    uint32_t                signature;         /* "STMP" */

    ngx_uint_t              id;
    ngx_connection_t       *connection;

    ngx_str_t               out;       // write()s output pointer
    ngx_buf_t              *buffer;    // input buffer
    u_char                 *bufout;    // output buffer

//    void                  **ctx;       // config context
    void                  **main_conf; // xtomp{} config block
    void                  **srv_conf;  // server{} config block

    ngx_uint_t              xtomp_state;      // connection state

    unsigned                protocol:3;
    unsigned                blocked:1;        // read was blocked
    unsigned                quit:1;           // close connection at next opportunity
    unsigned                invalid_header:1; //
    unsigned                trusted:1;        // trusted session, meaning not from internet or out of server owners control
    unsigned                web:1;            // port used is web like (80 81 or 8080)
    unsigned                res1:1;            // reserved for future use
    unsigned                res2:1;            // port used is web like (80 81 or 8080)
    unsigned                usr1:1;            // user flags for extensions
    unsigned                usr2:1;            //
    unsigned                usr3:1;            //
    unsigned                usr4:1;            //


    ngx_str_t              *addr_text;
    ngx_str_t               host;
    ngx_str_t               login;
    ngx_str_t               cmd;
    ngx_uint_t              heart_beat_read;
    ngx_uint_t              heart_beat_write;

    ngx_uint_t              command;       // STOMP command e.g. CONNECT or SEND
    xtomp_message_t        *message;       // message being uploaded
    off_t                   expected_len;  // -1 for read text to 0

    xtomp_mq_t             *mq;            // messages to be delivered
    ngx_uint_t              mq_size;       // number of undelivered messages

    xtomp_subscriber_t     *subs[XTOMP_MAX_SUBS];  // slots for subscriptions to destinations
    ngx_uint_t              subs_size;             // number of subscriptions

    xtomp_ws_ctx_t         *ws;            // WebSocket context or NULL
    unsigned                ws_demunge:1;       // do demunging i.e. we have read all the plain HTTP stuff and upgraded
    // WTF I tried moving this bit field to xtomp_ws_ctx_t it breaks if I use the syntax s->ws->demunge = 1;

    /* used to parse STOMP headers */

    ngx_uint_t              header_hash;       // hashcode of header being read

    u_char                 *header_name_start; // start of header name string
    u_char                 *header_name_end;   // end of header name string
    u_char                 *header_start;      // start of header value string
    u_char                 *header_end;        // end of header value string

    /* used to parse STOMP command (and headers) */

    ngx_uint_t              state;             // parser state
    u_char                 *cmd_start;         // start of command string

} xtomp_session_t;



typedef enum {
    xtomp_ack_auto = 0,
    xtomp_ack_client,
    xtomp_ack_client_individual,
} xtomp_ack_e;

struct xtomp_subscriber_s {
    xtomp_session_t            *sess;
    xtomp_core_dest_conf_t     *dest;
    ngx_table_elt_t            *filter;    // memory owned by sub

    ngx_int_t                   id;        // subscription id
    ngx_uint_t                  last_msg;  // TODO last fully delivered message
    time_t                      timestamp; // start time
    unsigned                    ack:2;     // auto|client|client-individual
    unsigned                    gone:1;    // 1 = client has disconnected

    xtomp_subscriber_t         *prev;
    xtomp_subscriber_t         *next;
};


typedef ngx_int_t (*xtomp_header_handler_pt)(xtomp_session_t *s, ngx_table_elt_t *h, ngx_uint_t offset);


typedef struct {
    ngx_str_t                   name;
    ngx_uint_t                  offset;
    xtomp_header_handler_pt     handler;
} xtomp_header_t;


typedef struct {
    ngx_str_t              *client;
    xtomp_session_t        *session;
} xtomp_log_ctx_t;


struct xtomp_message_chunk_s {
    ngx_str_t                  *data[XTOMP_MESSAGE_CHUNKS]; // Should not be treated as 0 terminated, binary data plus length
    ngx_int_t                   pos;  // -1 or position in the array of last chunk
    xtomp_message_chunk_t      *next;
};

struct xtomp_message_s {
    ngx_uint_t                   id;           // incrementing index
    ngx_str_t                   *destination;  // destination name + probably need vhost name too
    time_t                       timestamp;    // time the message was created (seconds from epoc)
    time_t                       expiry;       // expiry time in (seconds from epoc)
    off_t                        length;       // full length of message
    ngx_table_elt_t             *hdrs[XTOMP_MAX_HDRS];

    xtomp_message_chunk_t       *chunks;       // message data, an array of strings even only one index in the array.
    ngx_uint_t                   refs;         // reference counter, counts time m is on any conn's mq
    ngx_uint_t                   delivered;    // # of clients delivered to
    unsigned                     defragged:1;  // defragged messages have 1 chunk and are zero terminated
    unsigned                     sent:1;       // flag when all consumers have acked i
    unsigned                     conn:1;       // mem ownd by the conn
    unsigned                     dest:1;       // mem ownd by the dest
    unsigned                     constant:1;   // the message is a single const string and should not be freed
    unsigned                     http:1;
};


// function pointers 
typedef void (*xtomp_init_session_pt)(xtomp_session_t *s, ngx_connection_t *c);
typedef void (*xtomp_init_protocol_pt)(ngx_event_t *rev);
typedef void (*xtomp_auth_state_pt)(ngx_event_t *rev);
typedef ngx_int_t (*xtomp_parse_command_pt)(xtomp_session_t *s);
typedef ngx_int_t (*xtomp_dest_iter_pt)(xtomp_core_dest_conf_t *dest, void* data, xtomp_message_t *m);


struct xtomp_protocol_s {
    ngx_str_t                   name;
    in_port_t                   port[2];
    ngx_uint_t                  type;

    xtomp_init_session_pt    init_session;
    xtomp_init_protocol_pt   init_protocol;
    xtomp_parse_command_pt   parse_command;
};


typedef struct {
    xtomp_protocol_t           *protocol;

    void                       *(*create_main_conf)(ngx_conf_t *cf);
    char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(ngx_conf_t *cf);
    char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);

    void                       *(*create_dest_conf)(ngx_conf_t *cf);
    char                       *(*merge_dest_conf)(ngx_conf_t *cf, void *prev, void *conf);
} xtomp_module_t;

typedef struct {
    xtomp_core_dest_conf_t  *dest;
    xtomp_message_t         *mess;
} xtomp_cleaner_t;

#define XTOMP_MODULE        0x53544D50     /* "STMP" */

#define XTOMP_MAIN_CONF      0x02000000
#define XTOMP_SRV_CONF       0x04000000
#define XTOMP_DEST_CONF      0x08000000

#define XTOMP_MAIN_CONF_OFFSET  offsetof(xtomp_conf_ctx_t, main_conf)
#define XTOMP_SRV_CONF_OFFSET   offsetof(xtomp_conf_ctx_t, srv_conf)
#define XTOMP_DEST_CONF_OFFSET  offsetof(xtomp_conf_ctx_t, dest_conf)


#define xtomp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define xtomp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define xtomp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define xtomp_get_module_main_conf(s, module) (s)->main_conf[module.ctx_index]
#define xtomp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]
#define xtomp_get_module_dest_conf(r, module) (s)->dest_conf[module.ctx_index]


#define xtomp_conf_get_module_main_conf(cf, module) ((xtomp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define xtomp_conf_get_module_srv_conf(cf, module)  ((xtomp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define xtomp_conf_get_module_dest_conf(cf, module) ((xtomp_conf_ctx_t *) cf->ctx)->dest_conf[module.ctx_index]

void xtomp_increment(void);
void xtomp_decrement(void);

void xtomp_init_connection(ngx_connection_t *c);
void xtomp_send(ngx_event_t *wev);
ngx_int_t xtomp_read_command(xtomp_session_t *s, ngx_connection_t *conn);
void xtomp_close_connection(ngx_connection_t *conn);
u_char *xtomp_log_error(ngx_log_t *log, u_char *buf, size_t len);

//ngx_int_t xtomp_destination_add(ngx_conf_t *cf, ngx_queue_t **destinations, xtomp_core_dest_conf_t *cdcf);

ngx_int_t xtomp_init_headers_in_hash(ngx_conf_t *cf, xtomp_core_main_conf_t *cmcf);
ngx_int_t xtomp_init_headers_ws_in_hash(ngx_conf_t *cf, xtomp_core_main_conf_t *cmcf);

void xtomp_request_init_session(xtomp_session_t *s, ngx_connection_t *c);
void xtomp_request_init_protocol(ngx_event_t *rev);
void xtomp_request_process_commands(ngx_event_t *rev);
void xtomp_request_discard_frame(ngx_event_t *rev);

ngx_int_t xtomp_request_parse_command(xtomp_session_t *s);
ngx_int_t xtomp_request_parse_discard_frame(xtomp_session_t *s);
ngx_int_t xtomp_request_parse_discard_newlines(xtomp_session_t *s);


ngx_int_t xtomp_response_connect(xtomp_session_t *s, ngx_connection_t *c);
ngx_int_t xtomp_response_subscribe(xtomp_session_t *s, ngx_connection_t *c);
ngx_int_t xtomp_response_error_syntax(xtomp_session_t *s, ngx_connection_t *c);
ngx_int_t xtomp_response_error_general(xtomp_session_t *s, ngx_connection_t *c);
ngx_int_t xtomp_response_receipt(xtomp_session_t *s, ngx_connection_t *c);
ngx_int_t xtomp_response_error_dest_unknown(xtomp_session_t *s, ngx_connection_t *c);
ngx_int_t xtomp_response_error_message(xtomp_session_t *s, ngx_connection_t *c, char *error_message);

ngx_int_t xtomp_response_http_upgrade(xtomp_session_t *s, ngx_connection_t *c);
ngx_int_t xtomp_response_http_500(xtomp_session_t *s, ngx_connection_t *c);
ngx_int_t xtomp_response_http_200(xtomp_session_t *s, ngx_connection_t *c);



ngx_int_t xtomp_destination_put(xtomp_core_dest_conf_t *dest, xtomp_message_t *m);
ngx_int_t xtomp_destination_ack(xtomp_core_dest_conf_t  *dest, xtomp_message_t *m);
ngx_int_t xtomp_destination_nack(xtomp_core_dest_conf_t *dest, xtomp_message_t *m);
ngx_int_t xtomp_destination_send(xtomp_core_dest_conf_t *dest, xtomp_message_t *m);

xtomp_message_t* xtomp_destination_pop(xtomp_core_dest_conf_t *dest);
xtomp_message_t* xtomp_destination_peek(xtomp_core_dest_conf_t *dest);
xtomp_message_t* xtomp_destination_tail(xtomp_core_dest_conf_t *dest);
ngx_int_t xtomp_destination_iterate(xtomp_core_dest_conf_t *dest, void* data, xtomp_dest_iter_pt callback);

ngx_int_t xtomp_destination_subscribe(xtomp_session_t *s, ngx_connection_t *c, ngx_str_t *dest_name, ngx_int_t id, ngx_uint_t ack,
                                    xtomp_subscriber_t **sub_out);
void xtomp_destination_unsubscribe(xtomp_subscriber_t *sub);
ngx_int_t xtomp_destination_deliver(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *s);
xtomp_core_dest_conf_t* xtomp_destination_find(xtomp_core_srv_conf_t  *cscf, ngx_str_t *dest_name);
void xtomp_destination_clean_handler(ngx_event_t *clean_evt);
ngx_int_t xtomp_destination_logger(xtomp_core_dest_conf_t  *dest);
ngx_int_t xtomp_destination_logger_cc(ngx_log_t *log);
ngx_int_t xtomp_destination_check_write(xtomp_session_t *sess, ngx_str_t *dest_name);



xtomp_message_t* xtomp_message_create(xtomp_core_dest_conf_t *dest);
void xtomp_message_free(xtomp_message_t *m);
ngx_int_t xtomp_message_add_chunk(xtomp_message_t *m, ngx_str_t *chunk);
ngx_int_t xtomp_message_defrag(xtomp_message_t *m_to, xtomp_message_t *m_from);
xtomp_mq_t* xtomp_message_mq_push(xtomp_session_t *s, xtomp_core_dest_conf_t *dest, ngx_uint_t sub_id, xtomp_message_t *m);
xtomp_message_t* xtomp_message_mq_pop(xtomp_session_t *s);
xtomp_message_t* xtomp_message_mq_remove(xtomp_session_t *s, ngx_uint_t id);
xtomp_mq_t* xtomp_message_mq_find(xtomp_session_t *s, ngx_uint_t id);
ngx_str_t* xtomp_message_get_header(xtomp_message_t *m, ngx_str_t *name);



ngx_int_t xtomp_session_subs_add(xtomp_session_t *sess, xtomp_subscriber_t *sub);
ngx_int_t xtomp_session_subs_remove(xtomp_session_t *sess, xtomp_subscriber_t *sub);
void xtomp_session_close(xtomp_session_t *sess);
xtomp_subscriber_t* xtomp_session_subs_find(xtomp_session_t *sess, ngx_str_t *dest_name, ngx_int_t id);



ngx_int_t xtomp_headers_unset(xtomp_session_t *s);
ngx_int_t xtomp_headers_user_def_add(xtomp_session_t *s, ngx_table_elt_t *h);
ngx_int_t xtomp_headers_cpy(ngx_table_elt_t *h_in, ngx_table_elt_t **h_new);
ngx_int_t xtomp_headers_user_def_print(u_char *bufout, ngx_table_elt_t *user_def[]);
ngx_int_t xtomp_headers_len(ngx_table_elt_t *hdrs[]);
ngx_int_t xtomp_headers_move(xtomp_message_t *m, xtomp_session_t *s);



xtomp_subscriber_t* xtomp_destination_create_subscription(xtomp_core_dest_conf_t *dest, xtomp_session_t *sess, ngx_int_t id, ngx_uint_t ack);
void xtomp_destination_free_subscription(xtomp_subscriber_t *sub);
ngx_int_t xtomp_destination_subscribe_list(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub);
ngx_int_t xtomp_destination_unsubscribe_list(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub);
ngx_int_t xtomp_destination_send_list(xtomp_core_dest_conf_t *dest, xtomp_message_t *m);
ngx_int_t xtomp_destination_subscribe_hash(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub);
ngx_int_t xtomp_destination_unsubscribe_hash(xtomp_core_dest_conf_t *dest, xtomp_subscriber_t *sub);
ngx_int_t xtomp_destination_send_hash(xtomp_core_dest_conf_t *dest, xtomp_message_t *m, ngx_str_t *key);



ngx_int_t xtomp_ecg_connect(xtomp_session_t *s);
void xtomp_ecg_set_read_timeout(xtomp_session_t *s, ngx_event_t *rev);
void xtomp_ecg_set_write_timeout(xtomp_session_t *s, ngx_event_t *wev);
ngx_int_t xtomp_ecg_write_header(xtomp_session_t *s, u_char *bufout, ngx_int_t pos);
ngx_int_t xtomp_ecg_handle_write_timeout(ngx_event_t *wev);



ngx_int_t xtomp_auth_login_passcode(xtomp_session_t *sess, ngx_connection_t *c);
ngx_int_t xtomp_auth_sha(xtomp_session_t *sess, ngx_connection_t *c);
ngx_int_t xtomp_auth_set_login_name(xtomp_session_t *sess, ngx_connection_t *c);



ngx_int_t xtomp_log_init(xtomp_core_main_conf_t *cmcf);
ngx_int_t xtomp_log_store(xtomp_message_t *m);


void xtomp_request_process_body(ngx_event_t *rev);

/* STUB */
void xtomp_proxy_init(xtomp_session_t *s, ngx_addr_t *peer);
//void xtomp_auth_http_init(xtomp_session_t *s);
/**/


void* xtomp_malloc(size_t size);
void* xtomp_calloc(int count, size_t size);
void xtomp_free(void *p);
void* xtomp_perm_calloc(int count, size_t size);
ngx_int_t xtomp_strcmp(ngx_str_t *s1, ngx_str_t *s2);


// WEBSOCKETS: related functions


typedef enum {
    non_fin_text = 1,
    fin_cont,
    non_fin_cont,
    fin_text
} xtomp_frame_type_e;

ngx_int_t xtomp_ws_demunge(xtomp_session_t *s, u_char * recv_start);
ngx_int_t xtomp_ws_parse_upgrade(xtomp_session_t *s);
size_t xtomp_ws_frame_hdr(u_char *buf, size_t message_len, xtomp_frame_type_e type);



u_char * xtomp_base64(u_char *src, size_t len, size_t *out_len);


extern ngx_uint_t               xtomp_max_module;
extern ngx_module_t             xtomp_module;
extern ngx_module_t             xtomp_core_module;
extern xtomp_header_t           xtomp_headers_in[];
extern xtomp_header_t           xtomp_ws_headers_in[];
extern ngx_uint_t               xtomp_total;
extern ngx_uint_t               xtomp_count;
extern xtomp_core_srv_conf_t   *xtomp_core_conf;


#endif /* _XTOMP_H_INCLUDED_ */
