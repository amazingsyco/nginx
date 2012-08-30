
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>


#if (NGX_HAVE_GCC_ATTRIBUTE_ALIGNED)
#define ngx_aligned(x)        __attribute__(( aligned (x) ))
#else
#define ngx_aligned(x)
#endif


#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    *(uint32_t *) m == (c3 << 24 | c2 << 16 | c1 << 8 | c0)                   \
        && m[4] == c4

#else

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4

#endif


#if (NGX_HAVE_NONALIGNED)

#define ngx_spdy_frame_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define ngx_spdy_frame_parse_uint32(p)  ntohl(*(uint32_t *) (p))
#define ngx_spdy_frame_parse_len(p)    (ntohl(*(uint32_t *) (p)) >> 8)
#define ngx_spdy_frame_parse_sid(p)    (ntohl(*(uint32_t *) (p)) & 0x7fffffff)

#else

#define ngx_spdy_frame_parse_uint16(p) ((p)[0] << 8 | (p)[1])
#define ngx_spdy_frame_parse_uint32(p)                                        \
    ((p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])
#define ngx_spdy_frame_parse_len(p)    ((p)[0] << 16 | (p)[1] << 8 | (p)[2])
#define ngx_spdy_frame_parse_sid(p)                                           \
    (((p)[0] & 0x7f) << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#endif


#define NGX_SPDY_HEADER_SIZE          8

#define NGX_SPDY_CTRL_BYTE            0x80

#define NGX_SPDY_SYN_STREAM           1
#define NGX_SPDY_SYN_REPLY            2
#define NGX_SPDY_RST_STREAM           3
#define NGX_SPDY_SETTINGS             4
#define NGX_SPDY_NOOP                 5
#define NGX_SPDY_PING                 6
#define NGX_SPDY_GOAWAY               7
#define NGX_SPDY_HEADERS              8


#if (NGX_HAVE_LITTLE_ENDIAN)

#define NGX_SPDY_SYN_STREAM_HEAD                                              \
    (NGX_SPDY_SYN_STREAM << 24 | NGX_SPDY_VERSION << 8 | NGX_SPDY_CTRL_BYTE)

#define NGX_SPDY_SYN_REPLY_HEAD                                               \
    (NGX_SPDY_SYN_REPLY << 24 | NGX_SPDY_VERSION << 8 | NGX_SPDY_CTRL_BYTE)

#define NGX_SPDY_RST_STREAM_HEAD                                              \
    (NGX_SPDY_RST_STREAM << 24 | NGX_SPDY_VERSION << 8 | NGX_SPDY_CTRL_BYTE)

#define NGX_SPDY_SETTINGS_HEAD                                                \
    (NGX_SPDY_SETTINGS << 24 | NGX_SPDY_VERSION << 8 | NGX_SPDY_CTRL_BYTE)

#define NGX_SPDY_NOOP_HEAD                                                    \
    (NGX_SPDY_NOOP << 24 | NGX_SPDY_VERSION << 8 | NGX_SPDY_CTRL_BYTE)

#define NGX_SPDY_PING_HEAD                                                    \
    (NGX_SPDY_PING << 24 | NGX_SPDY_VERSION << 8 | NGX_SPDY_CTRL_BYTE)

#define NGX_SPDY_GOAWAY_HEAD                                                  \
    (NGX_SPDY_GOAWAY << 24 | NGX_SPDY_VERSION << 8 | NGX_SPDY_CTRL_BYTE)

#define NGX_SPDY_HEADERS_HEAD                                                 \
    (NGX_SPDY_HEADERS << 24 | NGX_SPDY_VERSION << 8 | NGX_SPDY_CTRL_BYTE)

#else

#define NGX_SPDY_SYN_STREAM_HEAD                                              \
    (NGX_SPDY_CTRL_BYTE << 24 | NGX_SPDY_VERSION << 16 | NGX_SPDY_SYN_STREAM)

#define NGX_SPDY_SYN_REPLY_HEAD                                               \
    (NGX_SPDY_CTRL_BYTE << 24 | NGX_SPDY_VERSION << 16 | NGX_SPDY_SYN_REPLY)

#define NGX_SPDY_RST_STREAM_HEAD                                              \
    (NGX_SPDY_CTRL_BYTE << 24 | NGX_SPDY_VERSION << 16 | NGX_SPDY_RST_STREAM)

#define NGX_SPDY_SETTINGS_HEAD                                                \
    (NGX_SPDY_CTRL_BYTE << 24 | NGX_SPDY_VERSION << 16 | NGX_SPDY_SETTINGS)

#define NGX_SPDY_NOOP_HEAD                                                    \
    (NGX_SPDY_CTRL_BYTE << 24 | NGX_SPDY_VERSION << 16 | NGX_SPDY_NOOP)

#define NGX_SPDY_PING_HEAD                                                    \
    (NGX_SPDY_CTRL_BYTE << 24 | NGX_SPDY_VERSION << 16 | NGX_SPDY_PING)

#define NGX_SPDY_GOAWAY_HEAD                                                  \
    (NGX_SPDY_CTRL_BYTE << 24 | NGX_SPDY_VERSION << 16 | NGX_SPDY_GOAWAY)

#define NGX_SPDY_HEADERS_HEAD                                                 \
    (NGX_SPDY_CTRL_BYTE << 24 | NGX_SPDY_VERSION << 16 | NGX_SPDY_HEADERS)

#endif


#define NGX_SPDY_PROTOCOL_ERROR            1
#define NGX_SPDY_INVALID_STREAM            2
#define NGX_SPDY_REFUSED_STREAM            3
#define NGX_SPDY_UNSUPPORTED_VERSION       4
#define NGX_SPDY_CANCEL                    5
#define NGX_SPDY_INTERNAL_ERROR            6
#define NGX_SPDY_FLOW_CONTROL_ERROR        7

#define NGX_SPDY_VERSION_HEADER_HASH       (ngx_uint_t) 107725790424ull
#define NGX_SPDY_SCHEME_HEADER_HASH        3386979749u
#define NGX_SPDY_METHOD_HEADER_HASH        3217412321u
#define NGX_SPDY_URL_HEADER_HASH           116079u

#define NGX_SPDY_SKIP_HEADERS_BUFFER_SIZE  4096

#define NGX_SPDY_CTRL_FRAME_BUFFER_SIZE    16


typedef struct {
    u_char    len;
    u_char    method[11];
    uint32_t  value;
} ngx_http_spdy_method_test_t;


static u_char ngx_http_spdy_dict[] =
    "options" "get" "head" "post" "put" "delete" "trace"
    "accept" "accept-charset" "accept-encoding" "accept-language"
    "authorization" "expect" "from" "host"
    "if-modified-since" "if-match" "if-none-match" "if-range"
    "if-unmodifiedsince" "max-forwards" "proxy-authorization"
    "range" "referer" "te" "user-agent"
    "100" "101" "200" "201" "202" "203" "204" "205" "206"
    "300" "301" "302" "303" "304" "305" "306" "307"
    "400" "401" "402" "403" "404" "405" "406" "407" "408" "409" "410"
    "411" "412" "413" "414" "415" "416" "417"
    "500" "501" "502" "503" "504" "505"
    "accept-ranges" "age" "etag" "location" "proxy-authenticate" "public"
    "retry-after" "server" "vary" "warning" "www-authenticate" "allow"
    "content-base" "content-encoding" "cache-control" "connection" "date"
    "trailer" "transfer-encoding" "upgrade" "via" "warning"
    "content-language" "content-length" "content-location"
    "content-md5" "content-range" "content-type" "etag" "expires"
    "last-modified" "set-cookie"
    "Monday" "Tuesday" "Wednesday" "Thursday" "Friday" "Saturday" "Sunday"
    "Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"
    "chunked" "text/html" "image/png" "image/jpg" "image/gif"
    "application/xml" "application/xhtml" "text/plain" "public" "max-age"
    "charset=iso-8859-1" "utf-8" "gzip" "deflate" "HTTP/1.1" "status"
    "version" "url";

static void *ngx_http_spdy_zalloc(void *opaque, u_int items, u_int size);
static void ngx_http_spdy_zfree(void *opaque, void *address);

static void ngx_http_spdy_read_handler(ngx_event_t *rev);
static void ngx_http_spdy_write_handler(ngx_event_t *wev);
static void ngx_http_spdy_keepalive_handler(ngx_event_t *rev);

#define ngx_http_spdy_streams_index_size(sscf)  (sscf->streams_index_mask + 1)
#define ngx_http_spdy_stream_index(sscf, sid)                                 \
    ((sid >> 1) & sscf->streams_index_mask)
static ngx_http_spdy_stream_t *ngx_http_spdy_get_stream_by_id(
    ngx_http_spdy_connection_t *sc, ngx_uint_t sid);
static void ngx_http_spdy_stream_index_cleanup(void *data);

static u_char *ngx_http_spdy_log_error_handler(ngx_http_request_t *r,
    ngx_http_request_t *sr, u_char *buf, size_t len);
static void ngx_http_spdy_writer(ngx_http_request_t *r);

static ngx_int_t ngx_http_spdy_init_default_request(
    ngx_http_spdy_connection_t *sc);
static ngx_http_request_t *ngx_http_spdy_create_request(
    ngx_http_spdy_connection_t *sc);

static void ngx_http_spdy_run_request(ngx_http_request_t *r);
static void ngx_http_spdy_terminate_request(ngx_http_request_t *r,
    ngx_int_t rc);
static void ngx_http_spdy_terminate_handler(ngx_http_request_t *r);
static void ngx_http_spdy_request_finalizer(ngx_http_request_t *r);
static void ngx_http_spdy_close_request(ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_spdy_free_request(ngx_http_request_t *r, ngx_int_t rc);

static void ngx_http_spdy_handle_connection(ngx_http_spdy_connection_t *sc);
static void ngx_http_spdy_finalize_connection(ngx_http_spdy_connection_t *sc,
    ngx_int_t rc);
static void ngx_http_spdy_close_connection(ngx_connection_t *c);

static ngx_int_t ngx_http_spdy_process_frame(ngx_http_spdy_connection_t *sc,
    u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_detect_settings_frame(
    ngx_http_spdy_connection_t *sc, u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_process_settings_frame(
    ngx_http_spdy_connection_t *sc, u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_skip_frame(ngx_http_spdy_connection_t *sc,
    u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_process_syn_stream(
    ngx_http_spdy_connection_t *sc, u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_process_data_frame(
    ngx_http_spdy_connection_t *sc, u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_process_rst_stream(
    ngx_http_spdy_connection_t *sc, u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_process_ping(ngx_http_spdy_connection_t *sc,
    u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_process_headers(ngx_http_spdy_connection_t *sc,
    u_char **pos, size_t size);
static ngx_int_t ngx_http_spdy_skip_headers(ngx_http_spdy_connection_t *sc,
    u_char **pos, size_t size);

static ngx_int_t ngx_http_spdy_parse_header(ngx_http_request_t *r,
    ngx_uint_t allow_underscores);
static ngx_int_t ngx_http_spdy_parse_version(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_parse_method(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_parse_uri(ngx_http_request_t *r);

static ngx_int_t ngx_http_spdy_alloc_large_header_buffer(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_construct_request_line(ngx_http_request_t *r);

static ngx_http_spdy_frame_chain_t *ngx_http_spdy_get_ctrl_frame(
    ngx_http_spdy_connection_t *sc);
#define ngx_http_spdy_free_ctrl_frame(sc, frame)                              \
    frame->next = sc->free_ctrl_frames;                                       \
    sc->free_ctrl_frames = frame

static void ngx_http_spdy_prepend_frame(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_frame_chain_t *frame);

static ngx_int_t ngx_http_spdy_send_rst_stream(ngx_http_spdy_connection_t *sc,
    ngx_uint_t sid, ngx_uint_t status);
static ngx_int_t ngx_http_spdy_send_settings(ngx_http_spdy_connection_t *sc);


static u_char *ngx_http_spdy_recv_buffer;


void
ngx_http_init_spdy(ngx_event_t *rev)
{
    int                          rc;
    ngx_connection_t            *c;
    ngx_http_spdy_srv_conf_t    *sscf;
    ngx_http_spdy_connection_t  *sc;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "init spdy request");

    sc = ngx_pcalloc(c->pool, sizeof(ngx_http_spdy_connection_t));
    if (sc == NULL) {
        ngx_http_spdy_close_connection(c);
        return;
    }

    sc->connection = c;

    c->data = sc;

    if (ngx_http_spdy_init_default_request(sc) != NGX_OK) {
        ngx_http_spdy_close_connection(c);
        return;
    }

    sc->handler = ngx_http_spdy_detect_settings_frame;

    sc->zstream_in.zalloc = ngx_http_spdy_zalloc;
    sc->zstream_in.zfree = ngx_http_spdy_zfree;
    sc->zstream_in.opaque = sc;

    rc = inflateInit(&sc->zstream_in);
    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "inflateInit() failed: %d", rc);
        ngx_http_spdy_close_connection(c);
        return;
    }

    sc->zstream_out.zalloc = ngx_http_spdy_zalloc;
    sc->zstream_out.zfree = ngx_http_spdy_zfree;
    sc->zstream_out.opaque = sc;

    sscf = ngx_http_get_module_srv_conf(sc->default_request,
                                        ngx_http_spdy_module);

    rc = deflateInit2(&sc->zstream_out,
                     (int) sscf->headers_comp,
                     Z_DEFLATED,
                     (int) sscf->headers_comp_wbits,
                     (int) sscf->headers_comp_memlevel,
                     Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "deflateInit2() failed: %d", rc);
        ngx_http_spdy_close_connection(c);
        return;
    }

    rc = deflateSetDictionary(&sc->zstream_out, ngx_http_spdy_dict,
                              sizeof(ngx_http_spdy_dict));
    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "deflateSetDictionary() failed: %d", rc);
        ngx_http_spdy_close_connection(c);
        return;
    }

    sc->streams_index = ngx_pcalloc(c->pool,
                                    ngx_http_spdy_streams_index_size(sscf)
                                    * sizeof(ngx_http_spdy_stream_t *));
    if (sc->streams_index == NULL) {
        ngx_http_spdy_close_connection(c);
        return;
    }

    rev->handler = ngx_http_spdy_read_handler;
    c->write->handler = ngx_http_spdy_write_handler;

    ngx_http_spdy_read_handler(rev);
}


ngx_int_t
ngx_http_spdy_alloc_recv_buffer(ngx_cycle_t *cycle)
{
    ngx_http_spdy_main_conf_t  *smcf;

    smcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_spdy_module);

    if (smcf) {
        ngx_http_spdy_recv_buffer = ngx_palloc(cycle->pool,
                                               smcf->recv_buffer_size);
        if (ngx_http_spdy_recv_buffer == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void *
ngx_http_spdy_zalloc(void *opaque, u_int items, u_int size)
{
    ngx_http_spdy_connection_t *sc = opaque;

    return ngx_palloc(sc->connection->pool, items * size);
}


static void
ngx_http_spdy_zfree(void *opaque, void *address)
{
#if 0
    ngx_http_spdy_connection_t *sc = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy zfree: %p", address);
#endif
}


static ngx_int_t
ngx_http_spdy_init_default_request(ngx_http_spdy_connection_t *sc)
{
    ngx_uint_t                  i;
    ngx_connection_t           *c;
    struct sockaddr_in         *sin;
    ngx_http_port_t            *port;
    ngx_http_request_t         *r;
    ngx_http_in_addr_t         *addr;
    ngx_http_addr_conf_t       *addr_conf;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_loc_conf_t   *clcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
    ngx_http_in6_addr_t        *addr6;
#endif

    c = sc->connection;

    r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        return NGX_ERROR;
    }

    r->signature = NGX_HTTP_MODULE;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in ngx_http_server_addr()
         * is required to determine a server address
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    r->virtual_names = addr_conf->virtual_names;

    /* the default server configuration for the address:port */
    cscf = addr_conf->default_server;

    r->main_conf = cscf->ctx->main_conf;
    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    r->read_event_handler = ngx_http_block_reading;

    r->main_filter_need_in_memory = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    c->log->file = clcf->error_log->file;
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
        c->log->log_level = clcf->error_log->log_level;
    }

    r->count = 1;
    r->method = NGX_HTTP_UNKNOWN;

    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    r->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;
    r->subrequests = NGX_HTTP_MAX_SUBREQUESTS + 1;

    r->http_state = NGX_HTTP_READING_REQUEST_STATE;

    r->valid_location = 1;
    r->log_handler = ngx_http_spdy_log_error_handler;

    r->gzip_tested = 1;
    r->gzip_ok = 1;

#if (NGX_STAT_STUB)
    r->stat_reading = 1;
#endif

    sc->default_request = r;

    return NGX_OK;
}


static ngx_http_request_t *
ngx_http_spdy_create_request(ngx_http_spdy_connection_t *sc)
{
    ngx_log_t                  *log;
    ngx_pool_t                 *pool;
    ngx_time_t                 *tp;
    ngx_event_t                *ev;
    ngx_connection_t           *fc;
    ngx_http_request_t         *r;
    ngx_http_log_ctx_t         *ctx;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    fc = sc->fake_connections;

    if (fc) {
        sc->fake_connections = fc->data;

    } else {
        fc = ngx_palloc(sc->connection->pool, sizeof(ngx_connection_t));
        if (fc == NULL) {
            return NULL;
        }
    }

    ngx_memcpy(fc, sc->connection, sizeof(ngx_connection_t));

    fc->sent = 0;
    fc->sndlowat = 1;
    fc->buffered = 0;

    cscf = ngx_http_get_module_srv_conf(sc->default_request,
                                        ngx_http_core_module);

    pool = ngx_create_pool(cscf->request_pool_size, sc->connection->log);
    if (pool == NULL) {
        return NULL;
    }

    ev = ngx_pcalloc(pool, sizeof(ngx_event_t));
    if (ev == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ev->ready = 1;

    fc->write = ev;
    fc->read = ev;

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    *log = *fc->log;
    fc->log = log;

    r = ngx_palloc(pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ngx_memcpy(r, sc->default_request, sizeof(ngx_http_request_t));

    r->pool = pool;
    r->connection = fc;

    fc->data = r;

    ctx = ngx_palloc(pool, sizeof(ngx_http_log_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ctx->connection = fc;
    ctx->request = r;
    ctx->current_request = r;

    log->data = ctx;

    r->header_in = ngx_create_temp_buf(pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    if (ngx_list_init(&r->headers_out.headers, pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NULL;
    }

    r->ctx = ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    r->variables = ngx_pcalloc(pool, cmcf->variables.nelts
                                        * sizeof(ngx_http_variable_value_t));
    if (r->variables == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    /*c->single_connection = 1;
    c->destroyed = 0;*/ //FIXME

    r->main = r;

    tp = ngx_timeofday();
    r->start_sec = tp->sec;
    r->start_msec = tp->msec;

    sc->connection->requests++;

#if (NGX_STAT_STUB)

    if (sc->processing) {
        (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
    }

    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
    (void) ngx_atomic_fetch_add(ngx_stat_requests, 1);

#endif

    return r;
}


static void
ngx_http_spdy_read_handler(ngx_event_t *rev)
{
    u_char                      *p, *end;
    size_t                       available;
    ssize_t                      n;
    ngx_int_t                    rc;
    ngx_uint_t                   rest;
    ngx_connection_t            *c;
    ngx_http_spdy_main_conf_t   *smcf;
    ngx_http_spdy_connection_t  *sc;

    c = rev->data;
    sc = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    sc->active = 1;

    smcf = ngx_http_get_module_main_conf(sc->default_request,
                                         ngx_http_spdy_module);

    available = smcf->recv_buffer_size - NGX_SPDY_STATE_BUFFER_SIZE + 1;

    rc = sc->waiting ? NGX_AGAIN : NGX_DONE;
    rest = sc->buffer_used;

    do {
        p = ngx_http_spdy_recv_buffer;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                               "SPDY rest %ui", rest);

        ngx_memcpy(p, sc->buffer, NGX_SPDY_STATE_BUFFER_SIZE);

        n = c->recv(c, p + rest, available - rest);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == 0 && (sc->waiting || sc->processing)) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed prematurely connection");
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_http_spdy_finalize_connection(sc,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        n += rest;
        end = p + n;

        do {
            rc = sc->handler(sc, &p, n);

            n = end - p;

            if (rc == NGX_AGAIN) {
                ngx_memcpy(sc->buffer, p, NGX_SPDY_STATE_BUFFER_SIZE);
                break;
            }

            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0, "SPDY ERROR");
                ngx_http_spdy_finalize_connection(sc,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

        } while (n);

        rest = n;

#if (NGX_DEBUG)
        if (rest > NGX_SPDY_STATE_BUFFER_SIZE) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "spdy state buffer overflow: "
                          "%i bytes required", n);
            ngx_http_spdy_finalize_connection(sc, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
#endif

    } while (rev->ready);

    sc->buffer_used = rest;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    sc->active = 0;

    if (sc->out_frames && c->write->ready) {
        ngx_post_event(c->write, &ngx_posted_events);
    }

    if (rc == NGX_AGAIN) {
        sc->waiting = 1;
    }

    if (sc->processing) {
        if (rev->timer_set) {
            ngx_del_timer(rev);
        }
        return;
    }

    ngx_http_spdy_handle_connection(sc);
}


static void
ngx_http_spdy_write_handler(ngx_event_t *wev)
{
    size_t                        sent;
    ngx_chain_t                  *chain, *cl, *ln;
    ngx_connection_t             *c, *fc;
    ngx_http_log_ctx_t           *ctx;
    ngx_http_request_t           *r;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_spdy_connection_t   *sc;
    ngx_http_spdy_frame_chain_t  *frame, *fn;

    c = wev->data;
    sc = c->data;

    if (wev->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "SPDY DEBUG: write event timed out");
        return; //FIXME
    }

    if (sc->out_frames == NULL && !c->buffered) {
        return; //FIXME
    }

    sc->active = 1;
    sc->out_incomplete = 0;

    do {
        cl = sc->out;

        c->sent = 0;

        chain = c->send_chain(c, cl, 0);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "spdy write handler send chain %p, sent:%uz",
                       chain, c->sent);

        if (chain == NGX_CHAIN_ERROR) {
            ngx_http_spdy_finalize_connection(sc,
                                              NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        sent = c->sent;

        frame = sc->out_frames;

        sc->out = NULL;
        sc->out_frames = NULL;

        for ( /* void */ ; cl != chain; cl = ln) {

            ln = cl->next;

            if (cl != frame->last) {
                continue;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "spdy frame complete %p %uz",
                           frame, frame->size);

            sent -= frame->size;

            fn = frame->next;

            r = frame->request;

            if (r == NULL) {
                ngx_http_spdy_free_ctrl_frame(sc, frame);
                frame = fn;
                continue;
            }

            fc = r->connection;

            fc->sent += frame->size;

            ngx_http_spdy_filter_free_data_frame(frame);
            frame = fn;

            r = fc->data;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "spdy run request: \"%V?%V\"", &r->uri, &r->args);

            ctx = fc->log->data;
            ctx->current_request = r;

            fc->write->delayed = 0;

            r->write_event_handler(r);
            ngx_http_run_posted_requests(fc);
        }

        if (cl) {
            fn = frame;

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "spdy frame incomplete %p %uz of %uz",
                           fn, sent, fn->size);

            if (sent) {
                fn->size -= sent;

                r = frame->request;
                if (r) {
                    r->connection->sent += sent;
                }
            }

            fn->blocked = 1;

            if (sc->out_frames) {

                while (frame->next) {
                    frame = frame->next;
                }

                frame->next = sc->out_frames;
                frame->last->next = sc->out;
            }

            sc->out_frames = fn;
            sc->out = cl;

            sc->out_incomplete = 1;

            break;
        }

    } while (sc->out_frames && wev->ready);

    clcf = ngx_http_get_module_loc_conf(sc->default_request,
                                        ngx_http_core_module);

    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    sc->active = 0;

    if (sc->processing) {
        return;
    }

    ngx_http_spdy_handle_connection(sc);
}


static ngx_http_spdy_stream_t *
ngx_http_spdy_get_stream_by_id(ngx_http_spdy_connection_t *sc,
    ngx_uint_t sid)
{
    ngx_http_spdy_stream_t    *stream;
    ngx_http_spdy_srv_conf_t  *sscf;

    sscf = ngx_http_get_module_srv_conf(sc->default_request,
                                        ngx_http_spdy_module);

    stream = sc->streams_index[ngx_http_spdy_stream_index(sscf, sid)];

    while (stream) {
        if (stream->id == sid) {
            return stream;
        }

        stream = stream->index;
    }

    return NULL;
}


static void
ngx_http_spdy_stream_index_cleanup(void *data)
{
    ngx_http_request_t  *r = data;

    ngx_http_spdy_stream_t     **index, *stream, *cs;
    ngx_http_spdy_srv_conf_t    *sscf;
    ngx_http_spdy_connection_t  *sc;

    stream = r->spdy_stream;
    sc = stream->connection;

    sscf = ngx_http_get_module_srv_conf(sc->default_request,
                                        ngx_http_spdy_module);

    index = sc->streams_index + ngx_http_spdy_stream_index(sscf, stream->id);

    for ( ;; ) {
        cs = *index;

        if (cs == NULL) {
            return;
        }

        if (cs == stream) {
            *index = cs->index;
            return;
        }

        index = &cs->index;
    }
}


static ngx_int_t
ngx_http_spdy_process_frame(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    u_char                  *p, flags;
    size_t                   length;
    uint32_t                 head;
    ngx_http_spdy_stream_t  *stream;

    if (size < 8) {
        return NGX_AGAIN;
    }

    p = *pos;

#if (NGX_HAVE_NONALIGNED)
    head = *(uint32_t *) p;
#else
    head = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
#endif

    flags = p[4];
    length = ngx_spdy_frame_parse_len(p + 5);

    sc->length = length;
    sc->flags = flags;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy process frame head:%ui f:%ui l:%ui",
                   head, flags, length);

    *pos += 8;

    switch (head) {

    case NGX_SPDY_SYN_STREAM_HEAD:
        sc->handler = ngx_http_spdy_process_syn_stream;
        return NGX_OK;

    case NGX_SPDY_SYN_REPLY_HEAD:
        //TODO log
        return NGX_ERROR;

    case NGX_SPDY_RST_STREAM_HEAD:
        sc->handler = ngx_http_spdy_process_rst_stream;
        return NGX_OK;

    case NGX_SPDY_SETTINGS_HEAD:
        //TODO
        sc->handler = ngx_http_spdy_skip_frame;
        return NGX_OK;

    case NGX_SPDY_NOOP_HEAD:
        if (flags != 0 || length != 0) {
            //TODO log
            return NGX_ERROR;
        }
        return NGX_OK;

    case NGX_SPDY_PING_HEAD:
        sc->handler = ngx_http_spdy_process_ping;
        return NGX_OK;

    case NGX_SPDY_GOAWAY_HEAD:
        //TODO
        sc->handler = ngx_http_spdy_skip_frame;
        return NGX_OK;

    case NGX_SPDY_HEADERS_HEAD:
        //TODO log
        return NGX_ERROR;
    }

    head = ntohl(head);

    if (head >> 31) {
        //TODO version & type check
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "spdy unknown frame %ui", head);

        sc->handler = ngx_http_spdy_skip_frame;

        return NGX_OK;
    }

    stream = ngx_http_spdy_get_stream_by_id(sc, head);

    if (stream == NULL || stream->request->discard_body) {
        sc->handler = ngx_http_spdy_skip_frame;
        return NGX_OK;
    }

    if (stream->half_closed) {
        //TODO log && error handling
        return NGX_ERROR;
    }

    sc->stream = stream;
    sc->handler = ngx_http_spdy_process_data_frame;

    return ngx_http_spdy_process_data_frame(sc, pos, size - 8); //FIXME
}


static ngx_int_t
ngx_http_spdy_detect_settings_frame(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    u_char  *p;

    if (size < 8) {
        return NGX_AGAIN;
    }

    p = *pos;

#if (NGX_HAVE_NONALIGNED)
    if (*(uint32_t *) p != NGX_SPDY_SETTINGS_HEAD) {
#else
    if (p[0] != 0x80
        || p[1] != NGX_SPDY_VERSION
        || p[2] != 0x00
        || p[3] != NGX_SPDY_SETTINGS)
    {
#endif
        ngx_http_spdy_send_settings(sc);

        sc->handler = ngx_http_spdy_process_frame;
        return NGX_OK;
    }

    sc->length = ngx_spdy_frame_parse_len(p + 5);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy SETTINGS frame received, size: %ui",
                   sc->length);

    *pos += 8;

    sc->handler = ngx_http_spdy_process_settings_frame;
    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_process_settings_frame(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    u_char                    *p;
    ngx_uint_t                 v;
    ngx_http_spdy_srv_conf_t  *sscf;

    if (sc->headers == 0) {

        if (size < 4) {
            return NGX_AGAIN;
        }

        sc->headers = ngx_spdy_frame_parse_uint32(*pos);

        *pos += 4;
        size -= 4;
        sc->length -= 4;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "spdy SETTINGS frame consists of %ui entries",
                       sc->headers);
    }

    p = *pos;

    do {
        if (size < 8) {
            *pos = p;
            return NGX_AGAIN;
        }

        if (p[0] != 0x04) {
            p += 8;
            size -= 8;
            sc->length -= 8;
            continue;
        }

        v = ngx_spdy_frame_parse_uint32(p + 4);

        sscf = ngx_http_get_module_srv_conf(sc->default_request,
                                            ngx_http_spdy_module);

        if (v != sscf->concurrent_streams) {
            ngx_http_spdy_send_settings(sc);
        }

        sc->handler = ngx_http_spdy_skip_frame;
        return NGX_OK;

    } while (--sc->headers);

    ngx_http_spdy_send_settings(sc);

    sc->handler = ngx_http_spdy_process_frame;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_spdy_skip_frame(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    if (size < sc->length) {
        *pos += size;
        sc->length -= size;
        return NGX_AGAIN;
    }

    *pos += sc->length;
    sc->handler = ngx_http_spdy_process_frame;

    return NGX_DONE;
}


static ngx_int_t
ngx_http_spdy_process_syn_stream(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    u_char                    *p;
    ngx_uint_t                 sid, prio, index;
    ngx_http_cleanup_t        *cln;
    ngx_http_request_t        *r;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_spdy_srv_conf_t  *sscf;

    if (size < 10) {
        return NGX_AGAIN;
    }

    p = *pos;

    sc->length -= 10;
    *pos += 10;

    sid = ngx_spdy_frame_parse_sid(p);
    prio = p[5] >> 2;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy SYN_STREAM frame sid:%ui prio:%ui", sid, prio);

    sscf = ngx_http_get_module_srv_conf(sc->default_request,
                                        ngx_http_spdy_module);
    if (sc->processing == sscf->concurrent_streams) {
        ngx_http_spdy_send_rst_stream(sc, sid, NGX_SPDY_REFUSED_STREAM);

        sc->handler = ngx_http_spdy_skip_headers;
        return NGX_OK;
    }

    r = ngx_http_spdy_create_request(sc);
    if (r == NULL) {
        return NGX_ERROR;
    }

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_spdy_stream_t));
    if (stream == NULL) {
        return NGX_ERROR;
    }

    r->spdy_stream = stream;

    stream->id = sid;
    stream->request = r;
    stream->connection = sc;
    stream->priority = prio;
    stream->half_closed = sc->flags & NGX_SPDY_FLAG_FIN;

    index = ngx_http_spdy_stream_index(sscf, sid);

    stream->index = sc->streams_index[index];
    sc->streams_index[index] = stream;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_spdy_stream_index_cleanup;
    cln->data = r;

    sc->processing++;

    sc->stream = stream;

    sc->handler = ngx_http_spdy_process_headers;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_process_data_frame(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    u_char                   *p;
    ssize_t                   n;
    ngx_buf_t                *buf;
    ngx_uint_t                complete;
    ngx_temp_file_t          *tf;
    ngx_http_request_t       *r;
    ngx_http_request_body_t  *rb;

    if (size >= sc->length) {
        complete = 1;
        size = sc->length;

    } else {
        complete = 0;
        sc->length -= size;
    }

    r = sc->stream->request;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy DATA frame");

    if (!r->request_body) {
        if (ngx_http_spdy_init_request_body(r) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    rb = r->request_body;
    tf = rb->temp_file;
    buf = rb->buf;

    if (size) {
        if (size > (size_t) rb->rest) {
            return NGX_ERROR;
        }

        rb->rest -= size;
        p = *pos;

        if (tf) {
            buf->start = p;
            buf->pos = p;

            p += size;

            buf->end = p;
            buf->last = p;

            n = ngx_write_chain_to_temp_file(tf, rb->bufs);

            /* TODO: n == 0 or not complete and level event */

            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            tf->offset += n;

        } else {
            buf->last = ngx_cpymem(buf->last, p, size);
            p += size;
        }

        *pos = p;
    }

    if (!complete) {
        return NGX_AGAIN;
    }

    sc->handler = ngx_http_spdy_process_frame;

    if (sc->flags & NGX_SPDY_FLAG_FIN) {

        sc->stream->half_closed = 1;

        if (tf) {
            ngx_memzero(buf, sizeof(ngx_buf_t));

            buf->in_file = 1;
            buf->file_pos = 0;
            buf->file_last = tf->file.offset;
            buf->file = &tf->file;

            rb->buf = NULL;
        }

        if (rb->post_handler) {
            rb->post_handler(r);
        }
    }

    return NGX_DONE;
}


ngx_int_t
ngx_http_spdy_init_request_body(ngx_http_request_t *r)
{
    ngx_buf_t                 *buf;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        return NGX_ERROR;
    }

    r->request_body = rb;

    rb->rest = r->headers_in.content_length_n;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->request_body_in_file_only
        || (size_t) rb->rest > clcf->client_body_buffer_size)
    {
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;

        if (r->spdy_stream->half_closed) {
            if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                         tf->persistent, tf->clean, tf->access)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        buf = ngx_calloc_buf(r->pool);
        if (buf == NULL) {
            return NGX_ERROR;
        }

    } else {

        if (rb->rest == 0) {
            return NGX_OK;
        }

        buf = ngx_create_temp_buf(r->pool, rb->rest);
        if (buf == NULL) {
            return NGX_ERROR;
        }
    }

    rb->buf = buf;

    rb->bufs = ngx_alloc_chain_link(r->pool);
    if (rb->bufs == NULL) {
        return NGX_ERROR;
    }

    rb->bufs->buf = buf;
    rb->bufs->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_process_rst_stream(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    u_char                  *p;
    ngx_uint_t               sid, status;
    ngx_http_request_t      *r;
    ngx_http_spdy_stream_t  *stream;

    if (size < 8) {
        return NGX_AGAIN;
    }

    p = *pos;

    if (sc->length != 8 || sc->flags) {
        return NGX_ERROR;
    }

    sid = ngx_spdy_frame_parse_sid(p);
    status = p[7];

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy RST_STREAM sid:%ui st:%ui", sid, status);


    switch (status) {

    case NGX_SPDY_PROTOCOL_ERROR:
        /* TODO */
        break;

    case NGX_SPDY_INVALID_STREAM:
        /* TODO */
        break;

    case NGX_SPDY_REFUSED_STREAM:
        /* TODO */
        break;

    case NGX_SPDY_UNSUPPORTED_VERSION:
        /* TODO */
        break;

    case NGX_SPDY_CANCEL:
        stream = ngx_http_spdy_get_stream_by_id(sc, sid);
        if (stream == NULL) {
            /* TODO false cancel */
            break;
        }

        r = stream->request;
        r->main->count++;

        ngx_http_spdy_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        ngx_http_run_posted_requests(r->connection);
        break;

    case NGX_SPDY_INTERNAL_ERROR:
        /* TODO */
        break;

    case NGX_SPDY_FLOW_CONTROL_ERROR:
        /* TODO */
        break;

    default:
        return NGX_ERROR;
    }

    *pos += 8;
    sc->handler = ngx_http_spdy_process_frame;

    return NGX_DONE;
}


static ngx_int_t
ngx_http_spdy_process_ping(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    u_char                       *p, *d;
    ngx_buf_t                    *buf;
    ngx_http_spdy_frame_chain_t  *frame;

    static u_char ping_header[] = { 0x80, 0x02, 0x00, 0x06,
                                    0x00, 0x00, 0x00, 0x04 };

    if (size < 4) {
        return NGX_AGAIN;
    }

    if (sc->length != 4) {
        return NGX_ERROR;
    }

    p = *pos;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0, "spdy PING frame");

    frame = ngx_http_spdy_get_ctrl_frame(sc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->size = 12;

    buf = frame->first->buf;

    d = buf->start;
    d = ngx_cpymem(d, ping_header, 8);
    d = ngx_cpymem(d, p, 4);

    buf->last = d;

    ngx_http_spdy_prepend_frame(sc, frame);

    sc->handler = ngx_http_spdy_process_frame;

    *pos += 4;

    return NGX_DONE;
}


static ngx_int_t
ngx_http_spdy_process_headers(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    int                         z;
    ngx_buf_t                  *buf;
    ngx_int_t                   rc;
    ngx_uint_t                  last;
    ngx_table_elt_t            *h;
    ngx_connection_t           *c;
    ngx_http_request_t         *r;

    c = sc->connection;
    r = sc->stream->request;
    buf = r->header_in;

    if (size >= sc->length) {
        last = 1;
        size = sc->length;

    } else {
        last = 0;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "spdy process headers %d of %d", size, sc->length);

    sc->zstream_in.next_in = *pos;
    sc->zstream_in.avail_in = size;
    sc->zstream_in.next_out = buf->last;
    sc->zstream_in.avail_out = buf->end - buf->last - 1;

    z = inflate(&sc->zstream_in, Z_NO_FLUSH);

    if (z == Z_NEED_DICT) {
        z = inflateSetDictionary(&sc->zstream_in, ngx_http_spdy_dict,
                                 sizeof(ngx_http_spdy_dict));
        if (z != Z_OK) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "spdy inflateSetDictionary() failed: %d", z);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "spdy inflateSetDictionary(): %d", z);

        z  = sc->zstream_in.avail_in ? inflate(&sc->zstream_in, Z_NO_FLUSH)
                                     : Z_OK;
    }

    if (z != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "spdy inflate() failed: %d", z);
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "spdy inflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   sc->zstream_in.next_in, sc->zstream_in.next_out,
                   sc->zstream_in.avail_in, sc->zstream_in.avail_out,
                   z);

    *pos = sc->zstream_in.next_in;

    sc->length -= (size - sc->zstream_in.avail_in);
    size = sc->zstream_in.avail_in;

    buf->last = sc->zstream_in.next_out;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "spdy headers decopressed: \"%*s\"",
                   buf->last - buf->pos, buf->pos);

    if (r->headers_in.headers.part.elts == NULL) {

        if (buf->last - buf->pos < 2) {
            return NGX_AGAIN;
        }

        sc->headers = ngx_spdy_frame_parse_uint16(buf->pos);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "spdy headers count: %i", sc->headers);

        buf->pos += 2;

        if (ngx_list_init(&r->headers_in.headers, r->pool, sc->headers + 3,
                          sizeof(ngx_table_elt_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_array_init(&r->headers_in.cookies, r->pool, 2,
                           sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    while (sc->headers) {

        rc = ngx_http_spdy_parse_header(r, 0);

        switch (rc) {

        case NGX_DONE:
            sc->headers--;

        case NGX_OK:
            break;

        case NGX_AGAIN:

            if (sc->zstream_in.avail_in) {

                rc = ngx_http_spdy_alloc_large_header_buffer(r);

                if (rc == NGX_DECLINED) {
                    /* TODO logging */
                    ngx_http_spdy_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);

                    sc->handler = ngx_http_spdy_skip_headers;
                    return NGX_OK;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                *buf->pos = '\0';

                buf = r->header_in;

                sc->zstream_in.next_out = buf->last;
                sc->zstream_in.avail_out = buf->end - buf->last - 1;

                z = inflate(&sc->zstream_in, Z_NO_FLUSH);

                if (z != Z_OK) {
                    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                                  "spdy inflate() failed: %d", z);
                    return NGX_ERROR;
                }

                *pos = sc->zstream_in.next_in;

                buf->last = sc->zstream_in.next_out;

                sc->length -= (size - sc->zstream_in.avail_in);
                size = sc->zstream_in.avail_in;

                continue;
            }

            if (last) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "again while last");
                return NGX_ERROR;
            }

            return NGX_AGAIN;

        default:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "NGX_ERROR");
            return NGX_ERROR;
        }

        if (r->invalid_header) {

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent invalid header line: \"%*s\"",
                          r->header_end - r->header_name_start,
                          r->header_name_start);
            continue;
        }

        /* a header line has been parsed successfully */

        switch (r->header_hash) {

        case NGX_SPDY_URL_HEADER_HASH:

            if (r->lowcase_index == 3) {

                if (ngx_http_spdy_parse_uri(r) != NGX_OK) {
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                               "http uri: \"%V\"", &r->uri);

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                               "http args: \"%V\"", &r->args);

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                               "http exten: \"%V\"", &r->exten);

                continue;
            }

            break;

        case NGX_SPDY_METHOD_HEADER_HASH:

            if (r->lowcase_index == 6) {

                if (ngx_http_spdy_parse_method(r) != NGX_OK) {
                    return NGX_ERROR;
                }

                continue;
            }

            break;

        case NGX_SPDY_SCHEME_HEADER_HASH:

            if (r->lowcase_index == 6) {
                r->schema_start = r->header_start;
                r->schema_end = r->header_end;
                continue;
            }

            break;

        case NGX_SPDY_VERSION_HEADER_HASH:

            if (r->lowcase_index == 7) {

                if (ngx_http_spdy_parse_version(r) != NGX_OK) {
                    return NGX_ERROR;
                }

                continue;
            }

            break;
        }

        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = r->header_hash;

        h->key.len = r->header_name_end - r->header_name_start;
        h->key.data = r->header_name_start;

        h->value.len = r->header_size;
        h->value.data = r->header_start;

        h->lowcase_key = h->key.data;
    }

    if (!last) {
        return NGX_AGAIN;
    }

    if (buf->pos != buf->last) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "end %i %d %d", last, buf->pos, buf->last);
        return NGX_ERROR;
    }

    *buf->pos = '\0';

    ngx_http_spdy_run_request(r);

    sc->handler = ngx_http_spdy_process_frame;

    return NGX_DONE;
}


static ngx_int_t
ngx_http_spdy_alloc_large_header_buffer(ngx_http_request_t *r)
{
    u_char                    *old, *new;
    size_t                     rest;
    ngx_buf_t                 *buf;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy alloc large header buffer");

    stream = r->spdy_stream;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (stream->header_buffers
        == (ngx_uint_t) cscf->large_client_header_buffers.num)
    {
        return NGX_DECLINED;
    }

    rest = r->header_in->last - r->header_in->pos;
 
    if (rest >= cscf->large_client_header_buffers.size) {
        return NGX_DECLINED;
    }

    buf = ngx_create_temp_buf(r->pool, cscf->large_client_header_buffers.size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy large header alloc: %p %uz",
                   buf->pos, buf->end - buf->last);

    old = r->header_in->pos;
    new = buf->pos;

    if (rest) {
        buf->last = ngx_cpymem(new, old, rest);
    }

    if (r->header_name_end > old) {
        r->header_name_end = new + (r->header_name_end - old);

    } else if (r->header_end > old) {
        r->header_end = new + (r->header_end - old);
    }

    r->header_in = buf;

    stream->header_buffers++;

    return NGX_OK;
}


static void
ngx_http_spdy_run_request(ngx_http_request_t *r)
{
    ngx_uint_t                  i;
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_connection_t           *fc;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    if (ngx_http_spdy_construct_request_line(r) != NGX_OK) {
        ngx_http_spdy_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    fc = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "spdy http request line: \"%V\"", &r->request_line);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0 ;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        hh = ngx_hash_find(&cmcf->headers_in_hash, h[i].hash,
                           h[i].lowcase_key, h[i].key.len);

        if (hh && hh->handler(r, &h[i], hh->offset) != NGX_OK) {
            ngx_http_spdy_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                       "http header: \"%V: %V\"", &h[i].key, &h[i].value);
    }

    r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

    if (ngx_http_process_request_header(r) != NGX_OK) {
        return;
    }

    if (r->plain_http) {
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client sent plain HTTP request to HTTPS port");
        ngx_http_spdy_finalize_request(r, NGX_HTTP_TO_HTTPS);
        return;
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    r->stat_reading = 0;
    (void) ngx_atomic_fetch_add(ngx_stat_writing, 1);
    r->stat_writing = 1;
#endif

    r->write_event_handler = ngx_http_core_run_phases;

    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(fc);
}


static ngx_int_t
ngx_http_spdy_skip_headers(ngx_http_spdy_connection_t *sc, u_char **pos,
    size_t size)
{
    int     n;
    u_char  buffer[NGX_SPDY_SKIP_HEADERS_BUFFER_SIZE];

    sc->zstream_in.next_in = *pos;
    sc->zstream_in.avail_in = (size < sc->length) ? size : sc->length;

    while (sc->zstream_in.avail_in) {
        sc->zstream_in.next_out = buffer;
        sc->zstream_in.avail_out = NGX_SPDY_SKIP_HEADERS_BUFFER_SIZE;

        n = inflate(&sc->zstream_in, Z_NO_FLUSH); //FIXME error handling
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0, "spdy inflate(): %d", n);

        if (n != Z_OK) {
            return NGX_ERROR;
        }
    }

    *pos = sc->zstream_in.next_in;

    if (size < sc->length) {
        sc->length -= size;
        return NGX_AGAIN;
    }

    sc->handler = ngx_http_spdy_process_frame;

    return NGX_DONE;
}


static ngx_int_t
ngx_http_spdy_parse_header(ngx_http_request_t *r,
    ngx_uint_t allow_underscores)
{
    u_char      *p, *end, ch;
    ngx_uint_t   len, hash;
    enum {
        sw_name_len = 0,
        sw_name,
        sw_value_len,
        sw_value
    } state;

    state = r->state;

    p = r->header_in->pos;
    end = r->header_in->last;

    switch (state) {

    case sw_name_len:

        if (end - p < 2) {
            return NGX_AGAIN;
        }

        len = ngx_spdy_frame_parse_uint16(p);

        if (!len) {
            return NGX_ERROR;
        }

        *p = '\0';

        p += 2;

        r->header_name_end = p + len;
        r->lowcase_index = len;
        r->invalid_header = 0;

        state = sw_name;

        /* fall through */

    case sw_name:

        if (r->header_name_end > end) {
            break;
        }

        r->header_name_start = p;

        hash = 0;

        for ( /* void */ ; p != r->header_name_end; p++) {

            ch = *p;

            if ((ch >= 'a' && ch <= 'z')
                || (ch == '-')
                || (ch >= '0' && ch <= '9')
                || (ch == '_' && allow_underscores))
            {
                hash = ngx_hash(hash, ch);
                continue;
            }

            return NGX_ERROR;
        }

        r->header_hash = hash;

        state = sw_value_len;

        /* fall through */

    case sw_value_len:

        if (end - p < 2) {
            break;
        }

        len = ngx_spdy_frame_parse_uint16(p);

        if (!len) {
            return NGX_ERROR;
        }

        *p = '\0';

        p += 2;

        r->header_end = p + len;

        state = sw_value;

        /* fall through */

    case sw_value:

        if (r->header_end > end) {
            break;
        }

        r->header_start = p;

        for ( /* void */ ; p != r->header_end; p++) {

            ch = *p;

            if (ch == '\0') {

                if (p == r->header_start) {
                    return NGX_ERROR;
                }

                r->header_size = p - r->header_start;
                r->header_in->pos = p + 1;

                return NGX_OK;
            }

            if (ch == CR || ch == LF) {
                return NGX_ERROR;
            }
        }

        r->header_size = p - r->header_start;
        r->header_in->pos = p;

        r->state = 0;

        return NGX_DONE;
    }

    r->header_in->pos = p;
    r->state = state;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_spdy_parse_version(ngx_http_request_t *r)
{
    u_char  *p, ch;

    if (r->http_protocol.len) {
        return NGX_ERROR;
    }

    p = r->header_start;

    if (r->header_size < 8 || !(ngx_str5cmp(p, 'H', 'T', 'T', 'P', '/'))) {
        return NGX_ERROR;
    }

    ch = *(p + 5);

    if (ch < '1' || ch > '9') {
        return NGX_ERROR;
    }

    r->http_major = ch - '0';

    for (p += 6; p != r->header_end - 2; p++) {

        ch = *p;

        if (ch < '0' || ch > '9') {
            return NGX_ERROR;
        }

        r->http_major = r->http_major * 10 + ch - '0';
    }

    if (*p != '.') {
        return NGX_ERROR;
    }

    ch = *(p + 1);

    if (ch < '0' || ch > '9') {
        return NGX_ERROR;
    }

    r->http_minor = ch - '0';

    for (p += 2; p != r->header_end; p++) {

        ch = *p;

        if (ch < '0' || ch > '9') {
            return NGX_ERROR;
        }

        r->http_minor = r->http_minor * 10 + ch - '0';
    }

    r->http_protocol.len = r->header_size;
    r->http_protocol.data = r->header_start;
    r->http_version = r->http_major * 1000 + r->http_minor;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_parse_method(ngx_http_request_t *r)
{
    u_char                       *p, *m;
    size_t                        k, len;
    ngx_uint_t                    n;
    ngx_http_spdy_method_test_t  *test;

    /*
     * This array takes less than 256 sequential bytes,
     * and if typical CPU cache line size is 64 bytes,
     * it is prefetched for 4 load operations.
     */
    static ngx_http_spdy_method_test_t  tests[]  ngx_aligned(64) = {
        { 3, "GET",       NGX_HTTP_GET },
        { 4, "POST",      NGX_HTTP_POST },
        { 4, "HEAD",      NGX_HTTP_HEAD },
        { 7, "OPTIONS",   NGX_HTTP_OPTIONS },
        { 8, "PROPFIND",  NGX_HTTP_PROPFIND },
        { 3, "PUT",       NGX_HTTP_PUT },
        { 5, "MKCOL",     NGX_HTTP_MKCOL },
        { 6, "DELETE",    NGX_HTTP_DELETE },
        { 4, "COPY",      NGX_HTTP_COPY },
        { 4, "MOVE",      NGX_HTTP_MOVE },
        { 9, "PROPPATCH", NGX_HTTP_PROPPATCH },
        { 4, "LOCK",      NGX_HTTP_LOCK },
        { 6, "UNLOCK",    NGX_HTTP_UNLOCK },
        { 5, "PATCH",     NGX_HTTP_PATCH },
        { 5, "TRACE",     NGX_HTTP_TRACE }
    };

    if (r->method_name.len) {
        return NGX_ERROR;
    }

    len = r->header_size;

    r->method_name.len = len;
    r->method_name.data = r->header_start;

    test = tests;
    n = sizeof(tests) / sizeof(ngx_http_spdy_method_test_t);

    do {
        if (len == test->len) {
            p = r->method_name.data;
            m = test->method;
            k = len;

            do {
                if (*p++ != *m++) {
                    goto next;
                }
            } while (--k);

            r->method = test->value;
            return NGX_OK;
        }

    next:
        test++;

    } while (--n);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_spdy_parse_uri(ngx_http_request_t *r)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (r->unparsed_uri.len) {
        return NGX_ERROR;
    }

    r->uri_start = r->header_start;
    r->uri_end = r->header_end;

    if (ngx_http_parse_uri(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r->args_start) {
        r->uri.len = r->args_start - 1 - r->uri_start;
    } else {
        r->uri.len = r->header_size;
    }

    if (r->complex_uri || r->quoted_uri) {

        r->uri.data = ngx_pnalloc(r->pool, r->uri.len + 1);
        if (r->uri.data == NULL) {
            return NGX_ERROR;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (ngx_http_parse_complex_uri(r, cscf->merge_slashes) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        r->uri.data = r->uri_start;
    }

    r->unparsed_uri.len = r->header_size;
    r->unparsed_uri.data = r->uri_start;

    r->valid_unparsed_uri = r->space_in_uri ? 0 : 1;

    if (r->uri_ext) {
        if (r->args_start) {
            r->exten.len = r->args_start - 1 - r->uri_ext;
        } else {
            r->exten.len = r->uri_end - r->uri_ext;
        }

        r->exten.data = r->uri_ext;
    }

    if (r->args_start && r->uri_end > r->args_start) {
        r->args.len = r->uri_end - r->args_start;
        r->args.data = r->args_start;
    }

#if (NGX_WIN32)
    {
    u_char  *p, *last;

    p = r->uri.data;
    last = r->uri.data + r->uri.len;

    while (p < last) {

        if (*p++ == ':') {

            /*
             * this check covers "::$data", "::$index_allocation" and
             * ":$i30:$index_allocation"
             */

            if (p < last && *p == '$') {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent unsafe win32 URI");
                return NGX_ERROR; //FIXME
            }
        }
    }

    p = r->uri.data + r->uri.len - 1;

    while (p > r->uri.data) {

        if (*p == ' ') {
            p--;
            continue;
        }

        if (*p == '.') {
            p--;
            continue;
        }

        break;
    }

    if (p != r->uri.data + r->uri.len - 1) {
        r->uri.len = p + 1 - r->uri.data;
        ngx_http_set_exten(r);
    }

    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_construct_request_line(ngx_http_request_t *r)
{
    u_char  *p;

    if (r->method_name.len == 0
        || r->unparsed_uri.len == 0
        || r->http_protocol.len == 0)
    {
        return NGX_ERROR;
    }

    r->request_line.len = r->method_name.len + 1
                          + r->unparsed_uri.len + 1
                          + r->http_protocol.len;

    p = ngx_pnalloc(r->pool, r->request_line.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    r->request_line.data = p;

    p = ngx_cpymem(p, r->method_name.data, r->method_name.len);

    *p++ = ' ';

    p = ngx_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);

    *p++ = ' ';

    ngx_memcpy(p, r->http_protocol.data, r->http_protocol.len + 1);

    /* Some modules expect the space character after method name */
    r->method_name.data = r->request_line.data;

    return NGX_OK;
}


static ngx_http_spdy_frame_chain_t *
ngx_http_spdy_get_ctrl_frame(ngx_http_spdy_connection_t *sc)
{
    ngx_pool_t                   *pool;
    ngx_chain_t                  *cl;
    ngx_http_spdy_frame_chain_t  *frame;

    frame = sc->free_ctrl_frames;

    if (frame) {
        sc->free_ctrl_frames = frame->next;

        cl = frame->first;
        cl->buf->pos = cl->buf->start;
        cl->next = NULL;

        frame->blocked = 0;

        return frame;
    }

    pool = sc->connection->pool;

    frame = ngx_pcalloc(pool, sizeof(ngx_http_spdy_frame_chain_t));
    if (frame == NULL) {
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_create_temp_buf(pool, NGX_SPDY_CTRL_FRAME_BUFFER_SIZE);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->buf->last_buf = 1;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;

    return frame;
}


void
ngx_http_spdy_append_frame(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_frame_chain_t *frame)
{
    ngx_http_spdy_frame_chain_t  *lf;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy append frame %p s:%z r:%p",
                   frame, frame->size, frame->request);

    frame->next = NULL;

    lf = sc->out_frames;

    if (lf == NULL) {
        sc->out_frames = frame;
        sc->out = frame->first;
        return;
    }

    for ( /* void */ ; lf->next; lf = lf->next);

    lf->next = frame;
    lf->last->next = frame->first;
}


static void
ngx_http_spdy_prepend_frame(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_frame_chain_t *frame)
{
    ngx_http_spdy_frame_chain_t  *ff;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy prepend frame %p s:%z r:%p",
                   frame, frame->size, frame->request);

    ff = sc->out_frames;

    if (ff == NULL) {
        sc->out_frames = frame;
        sc->out = frame->first;

        frame->next = NULL;

        return;
    }

    if (sc->out_incomplete) {
        frame->next = ff->next;
        frame->last->next = ff->last->next;

        ff->next = frame;
        ff->last->next = frame->first;

        return;
    }

    sc->out_frames = frame;
    sc->out = frame->first;

    frame->next = ff;
    frame->last->next = ff->first;
}


static ngx_int_t
ngx_http_spdy_send_rst_stream(ngx_http_spdy_connection_t *sc, ngx_uint_t sid,
    ngx_uint_t status)
{
    u_char                       *p;
    ngx_buf_t                    *buf;
    ngx_http_spdy_frame_chain_t  *frame;

    static u_char rst_stream_header[] = { 0x80, 0x02, 0x00, 0x03,
                                          0x00, 0x00, 0x00, 0x08 };

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy write RST_STREAM sid:%ui st:%ui", sid, status);

    frame = ngx_http_spdy_get_ctrl_frame(sc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->size = 16;

    buf = frame->first->buf;

    p = buf->start;
    p = ngx_cpymem(p, rst_stream_header, 8);

    p = ngx_spdy_frame_write_uint32(p, sid);
    p = ngx_spdy_frame_write_uint32(p, status);

    buf->last = p;

    ngx_http_spdy_append_frame(sc, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_send_settings(ngx_http_spdy_connection_t *sc)
{
    u_char                       *p;
    ngx_buf_t                    *buf;
    ngx_pool_t                   *pool;
    ngx_chain_t                  *cl;
    ngx_http_spdy_srv_conf_t     *sscf;
    ngx_http_spdy_frame_chain_t  *frame;

    static u_char settings_header[] = { 0x80, 0x02, 0x00, 0x04,
                                        0x01, 0x00, 0x00, 0x0c };

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy write SETTINGS frame");

    pool = sc->connection->pool;

    frame = ngx_palloc(pool, sizeof(ngx_http_spdy_frame_chain_t));
    if (frame == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    buf = ngx_create_temp_buf(pool, 20);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->last_buf = 1;

    cl->buf = buf;
    cl->next = NULL;

    frame->size = 20;
    frame->first = cl;
    frame->last = cl;
    frame->request = NULL;

    p = buf->pos;

    p = ngx_cpymem(p, settings_header, 8);
    p = ngx_spdy_frame_write_uint32(p, 1);

    *p++ = 0x04;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x01; //persistant

    sscf = ngx_http_get_module_srv_conf(sc->default_request,
                                        ngx_http_spdy_module);

    buf->last = ngx_spdy_frame_write_uint32(p, sscf->concurrent_streams);

    ngx_http_spdy_prepend_frame(sc, frame);

    return NGX_OK;
}


static void
ngx_http_spdy_writer(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy writer handler: \"%V?%V\"", &r->uri, &r->args);

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy writer output filter: %d, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    if (rc == NGX_ERROR) {
        ngx_http_spdy_finalize_request(r, rc);
        return;
    }

    if (r->buffered || r->postponed
        || (r == r->main && r->connection->buffered))
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "SPDY DEBUG: %i %i", r->buffered, r->postponed);
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy writer done: \"%V?%V\"", &r->uri, &r->args);

    r->write_event_handler = ngx_http_request_empty_handler;

    ngx_http_spdy_finalize_request(r, rc);
}


static u_char *
ngx_http_spdy_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
    u_char *buf, size_t len)
{
    char                      *uri_separator;
    u_char                    *p;
    ngx_http_upstream_t       *u;
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    p = ngx_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->request_line.data == NULL && r->request_start) {
        for (p = r->request_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - r->request_start;
        r->request_line.data = r->request_start;
    }

    if (r->request_line.len) {
        p = ngx_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = ngx_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (NGX_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = ngx_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = ngx_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = ngx_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        buf = p;
    }

    return buf;
}


void
ngx_http_spdy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t          *fc;
    ngx_http_request_t        *mr, *pr;
    ngx_http_core_loc_conf_t  *clcf;

    fc = r->connection;
    mr = r->main;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "spdy finalize request: %d, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == fc->data, mr->count);

    if (rc == NGX_DONE) {
        ngx_http_spdy_close_request(r, rc);
        return;
    }

    if (rc == NGX_OK && r->filter_finalize) {
        fc->error = 1;
    }

    if (rc == NGX_DECLINED) {
        r->content_handler = NULL;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    if (r != mr && r->post_subrequest) {
        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
    }

    if (rc == NGX_ERROR
        || rc == NGX_HTTP_REQUEST_TIME_OUT
        || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST
        || fc->error)
    {
        if (mr->blocked) {
            r->write_event_handler = ngx_http_spdy_request_finalizer;
        }

        ngx_http_spdy_terminate_request(r, rc); //FIXME internal error
        return;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE
        || rc == NGX_HTTP_CREATED
        || rc == NGX_HTTP_NO_CONTENT)
    {
        if (rc == NGX_HTTP_CLOSE) {
            ngx_http_spdy_terminate_request(r, rc); //FIXME finalize connection
            return;
        }

        ngx_http_spdy_finalize_request(r,
                                     ngx_http_special_response_handler(r, rc));
        return;
    }

    if (r != mr) {

        if (r->buffered || r->postponed) {

            r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;
            r->write_event_handler = ngx_http_spdy_writer;

            return;
        }

        pr = r->parent;

        if (r == fc->data) {

            mr->count--;
            mr->subrequests++;

            if (!r->logged) {

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->log_subrequest) {
                    ngx_http_log_request(r);
                }

                r->logged = 1;

            } else {
                ngx_log_error(NGX_LOG_ALERT, fc->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (pr->postponed && pr->postponed->request == r) {
                pr->postponed = pr->postponed->next;
            }

            fc->data = pr;

        } else {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                           "spdy finalize non-active request: \"%V?%V\"",
                           &r->uri, &r->args);

            r->write_event_handler = ngx_http_spdy_request_finalizer;

            if (r->waited) {
                r->done = 1;
            }
        }

        if (ngx_http_post_request(pr, NULL) != NGX_OK) {
            mr->count++;
            ngx_http_spdy_terminate_request(r, 0); //FIXME internal error
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                       "spdy wake parent request: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }

    if (r->buffered || fc->buffered || r->postponed || r->blocked) {

        r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;
        r->write_event_handler = ngx_http_spdy_writer;

        return;
    }

    if (r != fc->data) {
        ngx_log_error(NGX_LOG_ALERT, fc->log, 0,
                      "spdy finalize non-active request: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    r->done = 1;
    r->request_complete = 1;

    r->write_event_handler = ngx_http_request_empty_handler;

    ngx_http_spdy_close_request(r, 0);
}


static void
ngx_http_spdy_request_finalizer(ngx_http_request_t *r)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy finalizer done: \"%V?%V\"", &r->uri, &r->args);

    ngx_http_spdy_finalize_request(r, 0);
}


static void
ngx_http_spdy_terminate_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_uint_t                    blocked;
    ngx_chain_t                 **ln;
    ngx_http_cleanup_t           *cln;
    ngx_http_ephemeral_t         *e;
    ngx_http_spdy_connection_t   *sc;
    ngx_http_spdy_frame_chain_t  *frame, **fn;

    r = r->main;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy terminate request count:%d", r->count);

    if (rc > 0 && r->headers_out.status == 0) {
        r->headers_out.status = rc;
    }

    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy terminate cleanup count:%d blk:%d",
                   r->count, r->blocked);

    if (r->write_event_handler) {

        blocked = 0;

        sc = r->spdy_stream->connection;

        ln = &sc->out;
        fn = &sc->out_frames;

        for ( ;; ) {
            frame = *fn;

            if (frame == NULL) {
                break;
            }

            if (frame->request == r) {

                if (!frame->blocked) {
                    *ln = frame->last->next;
                    *fn = frame->next;
                    continue;
                }

                blocked = 1;
            }

            ln = &frame->last->next;
            fn = &frame->next;
        }

        if (r->blocked) {
            return;
        }

        r->posted_requests = NULL;
        r->write_event_handler = ngx_http_spdy_terminate_handler;

        if (blocked) {
            return;
        }

        e = ngx_http_ephemeral(r);
        (void) ngx_http_post_request(r, &e->terminal_posted_request);
        return;
    }

    ngx_http_spdy_close_request(r, rc);
}


static void
ngx_http_spdy_terminate_handler(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy terminate handler count:%d", r->count);

    r->count = 1;

    ngx_http_spdy_close_request(r, 0);
}


static void
ngx_http_spdy_close_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_spdy_connection_t  *sc;

    r = r->main;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "spdy request count is zero");
    }

    r->count--;

    if (r->count || r->blocked) {
        return;
    }

    sc = r->spdy_stream->connection;
    sc->processing--;

    ngx_http_spdy_free_request(r, rc);

    if (sc->processing || sc->active) {
        return;
    }

    ngx_http_spdy_handle_connection(sc);
}


static void
ngx_http_spdy_free_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t            *fc;
    ngx_http_cleanup_t          *cln;
    ngx_http_spdy_connection_t  *sc;

    fc = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0, "spdy free request");

    for (cln = r->cleanup; cln; cln = cln->next) {
        if (cln->handler) {
            cln->handler(cln->data);
        }
    }

    sc = r->main->spdy_stream->connection;

#if (NGX_STAT_STUB)

    if (r->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
    }

    if (sc->processing) {
        (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
    }

#endif

    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

    fc->log->action = "logging request";

    ngx_http_log_request(r);

    fc->log->action = "closing request";

    if (fc->write->timer_set) {
        ngx_del_timer(fc->write);
    }

    fc->destroyed = 1;

    fc->data = sc->fake_connections;
    sc->fake_connections = fc;
 
    ngx_destroy_pool(r->pool);
}


static void
ngx_http_spdy_handle_connection(ngx_http_spdy_connection_t *sc)
{
    ngx_connection_t          *c;
    ngx_http_spdy_srv_conf_t  *sscf;

    c = sc->connection;

    if (c->buffered) {
        return;
    }

    if (c->error) {
        ngx_http_spdy_close_connection(c);
        return;
    }

    sscf = ngx_http_get_module_srv_conf(sc->default_request,
                                        ngx_http_spdy_module);
    if (sc->waiting) {
        ngx_add_timer(c->read, sscf->recv_timeout);
        return;
    }

    if (ngx_terminate || ngx_exiting) {
        ngx_http_spdy_close_connection(c);
        return;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_ssl_free_buffer(c);
    }
#endif

    c->destroyed = 1;
    c->idle = 1;
    ngx_reusable_connection(c, 1);

    c->read->handler = ngx_http_spdy_keepalive_handler;

    ngx_add_timer(c->read, sscf->keepalive_timeout);
}


static void
ngx_http_spdy_keepalive_handler(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "spdy keepalive handler");

    if (rev->timedout || c->close) {
        ngx_http_spdy_close_connection(c);
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
#if (NGX_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            ngx_http_spdy_close_connection(c);
            return;
        }
    }

#endif

    c->destroyed = 0;
    c->idle = 0;
    ngx_reusable_connection(c, 0);

    rev->handler = ngx_http_spdy_read_handler;
    ngx_http_spdy_read_handler(rev);
}


static void
ngx_http_spdy_finalize_connection(ngx_http_spdy_connection_t *sc,
    ngx_int_t rc)
{
    ngx_uint_t                 i, size;
    ngx_event_t               *ev;
    ngx_connection_t          *c, *fc;
    ngx_http_request_t        *r;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_spdy_srv_conf_t  *sscf;

    c = sc->connection;

    if (!sc->processing) {
        ngx_http_spdy_close_connection(c);
        return;
    }

    c->error = 1;

    sc->out = NULL;
    sc->out_frames = NULL;
    sc->out_incomplete = 0;

    sc->active = 1;

    sscf = ngx_http_get_module_srv_conf(sc->default_request,
                                        ngx_http_spdy_module);

    size = ngx_http_spdy_streams_index_size(sscf);

    for (i = 0; i < size; i++) {
        stream = sc->streams_index[i];

        while (stream) {
            r = stream->request;

            stream = stream->index;

            fc = r->connection;
            fc->error = 1;

            r->main->count++;

            ngx_http_spdy_finalize_request(r, rc);
            ngx_http_run_posted_requests(fc);
        }
    }

    sc->active = 0;

    if (!sc->processing) {
        ngx_http_spdy_close_connection(c);
        return;
    }

    ev = c->read;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->prev) {
        ngx_delete_posted_event(ev);
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
        ngx_del_event(ev, NGX_READ_EVENT, 0);
    }

    ev = c->write;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->prev) {
        ngx_delete_posted_event(ev);
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
        ngx_del_event(ev, NGX_WRITE_EVENT, 0);
    }
}


static void
ngx_http_spdy_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "close spdy connection: %d", c->fd);

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_spdy_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}
