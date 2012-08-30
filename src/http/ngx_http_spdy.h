/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NGX_HTTP_SPDY_H_INCLUDED_
#define _NGX_HTTP_SPDY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>

#define NGX_SPDY_VERSION            2

#define NGX_SPDY_STATE_BUFFER_SIZE  9


typedef struct ngx_http_spdy_connection_s   ngx_http_spdy_connection_t;
typedef struct ngx_http_spdy_frame_chain_s  ngx_http_spdy_frame_chain_t;
typedef struct ngx_http_spdy_stream_s       ngx_http_spdy_stream_t;

typedef ngx_int_t (*ngx_http_spdy_handler_pt) (ngx_http_spdy_connection_t *sc,
    u_char **pos, size_t size);

struct ngx_http_spdy_connection_s {
    ngx_connection_t                *connection;
    ngx_http_request_t              *default_request;
    ngx_uint_t                       processing;

    u_char                           buffer[NGX_SPDY_STATE_BUFFER_SIZE];
    size_t                           buffer_used;
    ngx_http_spdy_handler_pt         handler;

    z_stream                         zstream_in;
    z_stream                         zstream_out;

    ngx_http_spdy_frame_chain_t     *free_ctrl_frames;

    ngx_http_spdy_stream_t         **streams_index;

    ngx_connection_t                *fake_connections;

    ngx_chain_t                     *out;
    ngx_http_spdy_frame_chain_t     *out_frames;

    ngx_http_spdy_stream_t          *stream;

    ngx_uint_t                       headers;
    size_t                           length;
    u_char                           flags;

    unsigned                         active:1;
    unsigned                         waiting:1;
    unsigned                         out_incomplete:1;
};

struct ngx_http_spdy_frame_chain_s {
    ngx_chain_t                     *first;
    ngx_chain_t                     *last;
    ngx_http_spdy_frame_chain_t     *next;

    size_t                           size;
    ngx_http_request_t              *request;

    unsigned                         blocked:1;
};


struct ngx_http_spdy_stream_s {
    ngx_uint_t                       id;
    ngx_http_request_t              *request;
    ngx_http_spdy_stream_t          *index;
    ngx_http_spdy_stream_t          *next;
    ngx_http_spdy_connection_t      *connection;

    ngx_uint_t                       header_buffers;

    unsigned                         priority:2;
    unsigned                         half_closed:1;
};


void ngx_http_init_spdy(ngx_event_t *rev);
void ngx_http_spdy_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

ngx_int_t ngx_http_spdy_alloc_recv_buffer(ngx_cycle_t *cycle);

ngx_int_t ngx_http_spdy_init_request_body(ngx_http_request_t *r);

void ngx_http_spdy_append_frame(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_frame_chain_t *frame);

void ngx_http_spdy_filter_free_data_frame(ngx_http_spdy_frame_chain_t *frame);


#define NGX_SPDY_FLAG_FIN             0x01
#define NGX_SPDY_FLAG_UNIDIRECTIONAL  0x02


#if (NGX_HAVE_NONALIGNED)

#if (NGX_HAVE_LITTLE_ENDIAN)
#define ngx_http_spdy_detect(p)  ((*(uint32_t *) p << 8) == 0x00028000)
#else
#define ngx_http_spdy_detect(p)  ((*(uint32_t *) p >> 8) == 0x00800200)
#endif

#define ngx_spdy_frame_write_uint16(p, s)                                     \
    (*(uint16_t *) (p) = htons(s), (p) + 2)

#define ngx_spdy_frame_write_uint32(p, s)                                     \
    (*(uint32_t *) (p) = htonl(s), (p) + 4)

#define ngx_spdy_frame_write_len_unsafe(p, s)                                 \
    (*(uint32_t *) (p) = htonl((s) << 8), (p) + 3)

#else

#define ngx_http_spdy_detect(p)  (p[0] == 0x80 && p[1] == 0x02 && p[2] == 0x00)

#define ngx_spdy_frame_write_uint16(p, s)                                     \
    ((p)[0] = (u_char) (s) >> 8, (p)[1] = (u_char) (s), (p) + 2)

#define ngx_spdy_frame_write_uint32(p, s)                                     \
    ((p)[0] = (u_char) (s) >> 24,                                             \
    (p)[1] = (u_char) (s) >> 16,                                              \
    (p)[2] = (u_char) (s) >> 8,                                               \
    (p)[3] = (u_char) (s), (p) + 4)

#define ngx_spdy_frame_write_len_unsafe ngx_spdy_frame_write_len

#endif

#define ngx_spdy_frame_write_len(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 16),                                           \
    (p)[1] = (u_char) ((s) >> 8),                                             \
    (p)[2] = (u_char) (s), (p) + 3)

#endif /* _NGX_HTTP_SPDY_H_INCLUDED_ */
