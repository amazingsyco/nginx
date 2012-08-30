
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <zlib.h>


#define NGX_SPDY_WRITE_BUFFERED  NGX_HTTP_WRITE_BUFFERED

#define ngx_http_spdy_header_sizeof(h)  (2 + sizeof(h) - 1)

#define ngx_http_spdy_header_write(p, h)                                      \
    ngx_cpymem(ngx_spdy_frame_write_uint16(p, sizeof(h) - 1), h, sizeof(h) - 1)


typedef struct {
    ngx_uint_t                    waiting;
    ngx_http_spdy_frame_chain_t  *free_frames;
    ngx_http_spdy_frame_chain_t  *free_data_frames;
} ngx_http_spdy_filter_ctx_t;


static ngx_http_spdy_frame_chain_t *ngx_http_spdy_filter_create_data_frame(
    ngx_http_request_t *r, ngx_uint_t len, ngx_uint_t last);
static ngx_http_spdy_frame_chain_t *ngx_http_spdy_filter_create_sync_frame(
    ngx_http_request_t *r);

static ngx_int_t ngx_http_spdy_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_spdy_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_spdy_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_spdy_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_spdy_filter_module_ctx,      /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_spdy_header_filter(ngx_http_request_t *r)
{
    int                           rc;
    size_t                        len;
    u_char                       *p;
    ngx_buf_t                    *b, *hb;
    ngx_str_t                     host;
    ngx_uint_t                    i, j, count, port;
    ngx_chain_t                  *cl;
    ngx_list_part_t              *part, *pt;
    ngx_table_elt_t              *header, *h;
    ngx_connection_t             *c;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_core_srv_conf_t     *cscf;
    ngx_http_spdy_filter_ctx_t   *ctx;
    ngx_http_spdy_connection_t   *sc;
    ngx_http_spdy_frame_chain_t  *frame;
    struct sockaddr_in           *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
#endif
    u_char                        addr[NGX_SOCKADDR_STRLEN];

    if (!r->spdy_stream) {
        return ngx_http_next_header_filter(r);
    }

    if (r->header_sent) {
        return NGX_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return NGX_OK;
    }

    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "spdy header filter");

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    switch (r->headers_out.status) {

    case NGX_HTTP_OK:
    case NGX_HTTP_PARTIAL_CONTENT:
        break;

    case NGX_HTTP_NOT_MODIFIED:
        r->header_only = 1;
        break;

    case NGX_HTTP_NO_CONTENT:
        r->header_only = 1;

        ngx_str_null(&r->headers_out.content_type);

        r->headers_out.content_length = NULL;
        r->headers_out.content_length_n = -1;

        /* fall through */

    default:
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;
    }

    len = 8 + 6 + 2
          + ngx_http_spdy_header_sizeof("version")
          + ngx_http_spdy_header_sizeof("HTTP/1.x")
          + ngx_http_spdy_header_sizeof("status")
          + ngx_http_spdy_header_sizeof("xxx");

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_out.server == NULL) {
        len += ngx_http_spdy_header_sizeof("server");
        len += clcf->server_tokens ? ngx_http_spdy_header_sizeof(NGINX_VER):
                                     ngx_http_spdy_header_sizeof("nginx");
    }

    if (r->headers_out.date == NULL) {
        len += ngx_http_spdy_header_sizeof("date")
               + ngx_http_spdy_header_sizeof("Wed, 31 Dec 1986 10:00:00 GMT");
    }

    if (r->headers_out.content_type.len) {
        len += ngx_http_spdy_header_sizeof("content-type")
               + 2 + r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += ngx_http_spdy_header_sizeof("content-length")
               + 2 + NGX_OFF_T_LEN;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += ngx_http_spdy_header_sizeof("last-modified")
               + ngx_http_spdy_header_sizeof("Wed, 31 Dec 1986 10:00:00 GMT");
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        r->headers_out.location->hash = 0;

        if (clcf->server_name_in_redirect) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            host = cscf->server_name;

        } else if (r->headers_in.server.len) {
            host = r->headers_in.server;

        } else {
            host.len = NGX_SOCKADDR_STRLEN;
            host.data = addr;

            if (ngx_connection_local_sockaddr(c, &host, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
            port = ntohs(sin6->sin6_port);
            break;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            port = 0;
            break;
#endif
        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;
            port = ntohs(sin->sin_port);
            break;
        }

        len += ngx_http_spdy_header_sizeof("location")
               + ngx_http_spdy_header_sizeof("https://")
               + host.len
               + r->headers_out.location->value.len;

        if (clcf->port_in_redirect) {

#if (NGX_HTTP_SSL)
            if (c->ssl)
                port = (port == 443) ? 0 : port;
            else
#endif
                port = (port == 80) ? 0 : port;

        } else {
            port = 0;
        }

        if (port) {
            len += sizeof(":65535") - 1;
        }

    } else {
        ngx_str_null(&host);
        port = 0;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        len += 2 + header[i].key.len + 2 + header[i].value.len;
    }

    hb = ngx_create_temp_buf(r->pool, len);
    if (hb == NULL) {
        return NGX_ERROR;
    }

    hb->last = ngx_http_spdy_header_write(hb->last + 2, "version");
    hb->last = ngx_http_spdy_header_write(hb->last, "HTTP/1.1");

    hb->last = ngx_http_spdy_header_write(hb->last, "status");
    hb->last = ngx_spdy_frame_write_uint16(hb->last, 3);
    hb->last = ngx_sprintf(hb->last, "%ui", r->headers_out.status);

    count = 2;

    if (r->headers_out.server == NULL) {
        hb->last = ngx_http_spdy_header_write(hb->last, "server");
        hb->last = clcf->server_tokens ?
                   ngx_http_spdy_header_write(hb->last, NGINX_VER):
                   ngx_http_spdy_header_write(hb->last, "nginx");
        count++;
    }

    if (r->headers_out.date == NULL) {
        hb->last = ngx_http_spdy_header_write(hb->last, "date");

        hb->last = ngx_spdy_frame_write_uint16(hb->last,
                                               ngx_cached_http_time.len);

        hb->last = ngx_cpymem(hb->last, ngx_cached_http_time.data,
                              ngx_cached_http_time.len);
        count++;
    }

    if (r->headers_out.content_type.len) {

        hb->last = ngx_http_spdy_header_write(hb->last, "content-type");

        p = hb->last + 2;

        hb->last = ngx_cpymem(p, r->headers_out.content_type.data,
                              r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            hb->last = ngx_cpymem(hb->last, "; charset=",
                                  sizeof("; charset=") - 1);
            hb->last = ngx_cpymem(hb->last, r->headers_out.charset.data,
                                  r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = hb->last - p;
            r->headers_out.content_type.data = p;
        }

        (void) ngx_spdy_frame_write_uint16(p - 2,
                                           r->headers_out.content_type.len);

        count++;
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        hb->last = ngx_http_spdy_header_write(hb->last, "content-length");

        p = hb->last + 2;

        hb->last = ngx_sprintf(p, "%O", r->headers_out.content_length_n);

        (void) ngx_spdy_frame_write_uint16(p - 2, hb->last - p);

        count++;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        hb->last = ngx_http_spdy_header_write(hb->last, "last-modified");

        p = hb->last + 2;

        hb->last = ngx_http_time(p, r->headers_out.last_modified_time);

        (void) ngx_spdy_frame_write_uint16(p - 2, hb->last - p);

        count++;
    }

    if (host.data) {

        hb->last = ngx_http_spdy_header_write(hb->last, "location");

        p = hb->last + 2;

        hb->last = ngx_cpymem(p, "http", sizeof("http") - 1);

#if (NGX_HTTP_SSL)
        if (c->ssl) {
            *hb->last++ ='s';
        }
#endif

        *hb->last++ = ':'; *hb->last++ = '/'; *hb->last++ = '/';
        hb->last = ngx_cpymem(hb->last, host.data, host.len);

        if (port) {
            hb->last = ngx_sprintf(hb->last, ":%ui", port);
        }

        hb->last = ngx_cpymem(hb->last, r->headers_out.location->value.data,
                              r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = hb->last - p;
        r->headers_out.location->value.data = p;
        ngx_str_set(&r->headers_out.location->key, "location");

        (void) ngx_spdy_frame_write_uint16(p - 2, r->headers_out.location->value.len);

        count++;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0 || header[i].hash == 2) {
            continue;
        }

        if ((header[i].key.len == 6
             && ngx_strncasecmp(header[i].key.data,
                                (u_char *) "status", 6) == 0)
            || (header[i].key.len == 7
                && ngx_strncasecmp(header[i].key.data,
                                   (u_char *) "version", 7) == 0))
        {
            header[i].hash = 0;
            continue;
        }

        hb->last = ngx_spdy_frame_write_uint16(hb->last, header[i].key.len);

        ngx_strlow(hb->last, header[i].key.data, header[i].key.len);
        hb->last += header[i].key.len;

        p = hb->last + 2;

        hb->last = ngx_cpymem(p, header[i].value.data, header[i].value.len);

        pt = part;
        h = header;

        for (j = i + 1; /* void */; j++) {

            if (j >= pt->nelts) {
                if (pt->next == NULL) {
                    break;
                }

                pt = pt->next;
                h = pt->elts;
                j = 0;
            }

            if (h[j].hash == 0 || h[j].hash == 2
                || h[j].key.len != header[i].key.len
                || ngx_strncasecmp(header[i].key.data, h[j].key.data,
                                   header[i].key.len))
            {
                continue;
            }

            *hb->last++ = '\0';

            hb->last = ngx_cpymem(hb->last, h[j].value.data, h[j].value.len);

            h[j].hash = 2;
        }

        (void) ngx_spdy_frame_write_uint16(p - 2, hb->last - p);

        count++;
    }

    (void) ngx_spdy_frame_write_uint16(hb->pos, count);

    /* TODO: better zlib overhead computation */
    b = ngx_create_temp_buf(r->pool, hb->last - hb->pos + 14 + 15);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last += 14;

    sc = r->spdy_stream->connection;

    sc->zstream_out.next_in = hb->pos;
    sc->zstream_out.avail_in = hb->last - hb->pos;
    sc->zstream_out.next_out = b->last;
    sc->zstream_out.avail_out = b->end - b->last;

    rc = deflate(&sc->zstream_out, Z_SYNC_FLUSH); //Z_FINISH);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "spdy deflate() failed: %d", rc);
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "spdy deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   sc->zstream_out.next_in, sc->zstream_out.next_out,
                   sc->zstream_out.avail_in, sc->zstream_out.avail_out,
                   rc);

    b->last = sc->zstream_out.next_out;

    len = b->last - b->pos - 8;

    p = b->pos;

#if (NGX_HAVE_NONALIGNED)

#if (NGX_HAVE_LITTLE_ENDIAN)
    *(uint32_t *) p = 0x02000280;
#else
    *(uint32_t *) p = 0x80020002;
#endif

#else
    p[0] = 0x80; p[1] = 0x02; p[2] = 0x00; p[3] = 0x02;

#endif

    if (r->header_only) {
        b->last_buf = 1;
        p[4] = 0x01;

    } else {
        p[4] = 0x00;
    }

    p = ngx_spdy_frame_write_len_unsafe(p + 5, len);

    (void) ngx_spdy_frame_write_uint32(p, r->spdy_stream->id);

    r->header_size = ngx_buf_size(b); //FIXME

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    frame = ngx_palloc(r->pool, sizeof(ngx_http_spdy_frame_chain_t));
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->first = cl;
    frame->last = cl;
    frame->size = r->header_size;
    frame->request = r;
    frame->blocked = 1;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_spdy_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->waiting = 1;

    ngx_http_set_ctx(r, ctx, ngx_http_spdy_filter_module);

    c->buffered |= NGX_SPDY_WRITE_BUFFERED;
    c->write->delayed = 1;

    ngx_http_spdy_append_frame(sc, frame);

    if (!sc->active && sc->connection->write->ready) {
        ngx_post_event(sc->connection->write, &ngx_posted_events);
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_spdy_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                         size;
    ngx_buf_t                    *b;
    ngx_uint_t                    last;
    ngx_chain_t                  *cl, *ll, *out, **ln;
    ngx_http_spdy_connection_t   *sc;
    ngx_http_spdy_filter_ctx_t   *ctx;
    ngx_http_spdy_frame_chain_t  *frame;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_spdy_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy body filter \"%V?%V\"", &r->uri, &r->args);

    if (in == NULL || r->header_only) {
ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SPDY DEBUG WAITED %i", ctx->waiting);
        if (ctx->waiting) {
            return NGX_AGAIN;
        }

        r->connection->buffered &= ~NGX_SPDY_WRITE_BUFFERED;

        return NGX_OK;
    }

    size = 0;
    ln = &out;
    ll = in;

    for ( ;; ) {
        b = ll->buf;
#if 1
        if (ngx_buf_size(b) == 0 && !ngx_buf_special(b)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zero size buf in spdy body filter "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          b->temporary,
                          b->recycled,
                          b->in_file,
                          b->start,
                          b->pos,
                          b->last,
                          b->file,
                          b->file_pos,
                          b->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        size += ngx_buf_size(b);
        cl->buf = b;

        *ln = cl;
        ln = &cl->next;

        if (ll->next == NULL) {
            break;
        }

        ll = ll->next;
    }

    *ln = NULL;

    last = b->last_buf;

    if (size || last) {
        frame = ngx_http_spdy_filter_create_data_frame(r, size, last);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->first->next = out;

    } else {
        frame = ngx_http_spdy_filter_create_sync_frame(r);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->first = out;
    }

    frame->last = cl; //FIXME

    r->connection->buffered |= NGX_SPDY_WRITE_BUFFERED;
    r->connection->write->delayed = 1;

    ctx->waiting++;

    sc = r->spdy_stream->connection;

    ngx_http_spdy_append_frame(sc, frame);

    if (!sc->active && sc->connection->write->ready) {
        ngx_post_event(sc->connection->write, &ngx_posted_events);
    }

    return NGX_AGAIN;
}


static ngx_http_spdy_frame_chain_t *
ngx_http_spdy_filter_create_data_frame(ngx_http_request_t *r, ngx_uint_t len,
    ngx_uint_t last)
{
    u_char                       *p;
    ngx_buf_t                    *buf;
    ngx_http_spdy_frame_chain_t  *frame;
    ngx_http_spdy_filter_ctx_t   *ctx;

    r = r->main;
 
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy create data frame len:%i last:%ui", len, last);

    ctx = ngx_http_get_module_ctx(r, ngx_http_spdy_filter_module);

    frame = ctx->free_data_frames;

    if (frame) {
        ctx->free_data_frames = frame->next;

        buf = frame->first->buf;

        p = buf->start;
        buf->pos = p;

        if (last) {
            p[4] = 1;
        }

        (void) ngx_spdy_frame_write_len(p + 5, len);

        frame->size = len + 8;
        frame->request = r;

        frame->blocked = 0;

        return frame;
    }

    frame = ngx_palloc(r->pool, sizeof(ngx_http_spdy_frame_chain_t));
    if (frame == NULL) {
        return NULL;
    }

    frame->first = ngx_alloc_chain_link(r->pool);
    if (frame->first == NULL) {
        return NULL;
    }

    buf = ngx_create_temp_buf(r->pool, 8);
    if (buf == NULL) {
        return NULL;
    }

    buf->tag = (ngx_buf_tag_t) &ngx_http_spdy_filter_module;

    p = buf->last;
    p = ngx_spdy_frame_write_uint32(p, r->spdy_stream->id);
    *p++ = last;
    buf->last = ngx_spdy_frame_write_len(p, len);

    frame->first->buf = buf;
    frame->size = 8 + len;
    frame->request = r;
    frame->blocked = 0;

    return frame;
}


static ngx_http_spdy_frame_chain_t *
ngx_http_spdy_filter_create_sync_frame(ngx_http_request_t *r)
{
    ngx_http_spdy_frame_chain_t  *frame;
    ngx_http_spdy_filter_ctx_t   *ctx;

    r = r->main;
 
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy create sync frame");

    ctx = ngx_http_get_module_ctx(r, ngx_http_spdy_filter_module);

    frame = ctx->free_frames;

    if (frame) {
        ctx->free_frames = frame->next;
        frame->size = 0;
        frame->blocked = 0;
        return frame;
    }

    frame = ngx_palloc(r->pool, sizeof(ngx_http_spdy_frame_chain_t));
    if (frame == NULL) {
        return NULL;
    }

    frame->size = 0;
    frame->request = r;
    frame->blocked = 0;

    return frame;
}


void
ngx_http_spdy_filter_free_data_frame(ngx_http_spdy_frame_chain_t *frame)
{
    ngx_chain_t                 *cl, *ln;
    ngx_http_request_t          *r;
    ngx_http_spdy_filter_ctx_t  *ctx;

    r = frame->request;
    ctx = ngx_http_get_module_ctx(r, ngx_http_spdy_filter_module);

    ctx->waiting--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SPDY FREE DATA %i", ctx->waiting);

    cl = frame->first;

    if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_spdy_filter_module) {
        cl = cl->next;
        frame->next = ctx->free_data_frames;                                                  \
        ctx->free_data_frames = frame;
    }

    do {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    } while (ln != frame->last);
}


static ngx_int_t
ngx_http_spdy_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_spdy_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_spdy_body_filter;

    return NGX_OK;
}
