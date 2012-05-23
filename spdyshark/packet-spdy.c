/* packet-spdy.c
 * Routines for SPDY packet disassembly
 * For now, the protocol spec can be found at
 * http://dev.chromium.org/spdy/spdy-protocol
 *
 * Copyright 2010, Google Inc.
 * Hasan Khalil <hkhalil@google.com>
 * Chris Bentzel <cbentzel@google.com>
 * Eric Shienbrood <ers@google.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Originally based on packet-http.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/base64.h>
#include <epan/emem.h>
#include <epan/stats_tree.h>

#include <epan/req_resp_hdrs.h>
#include "packet-spdy.h"
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-ssl.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>

#define SPDY_FIN  0x01
#define TCP_PORT_SPDY 6121
#define SSL_PORT_SPDY 443

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

/* The types of SPDY control frames */
typedef enum _spdy_type {
    SPDY_DATA,
    SPDY_SYN_STREAM,
    SPDY_SYN_REPLY,
    SPDY_RST_STREAM,
    SPDY_SETTINGS,
    SPDY_NOOP,
    SPDY_PING,
    SPDY_GOAWAY,
    SPDY_HEADERS,
    SPDY_WINDOW_UPDATE,
    SPDY_CREDENTIAL,
    SPDY_INVALID
} spdy_frame_type_t;

static const char *frame_type_names[] = {
    "DATA",
    "SYN_STREAM",
    "SYN_REPLY",
    "RST_STREAM",
    "SETTINGS",
    "NOOP",
    "PING",
    "GOAWAY",
    "HEADERS",
    "WINDOW_UPDATE",
    "CREDENTIAL",
    "INVALID"
};

typedef enum _spdy_rst_stream_status {
    INVALID_LOWER_BOUND = 0, /* Invalid value, lower bound for enum. */
    PROTOCOL_ERROR,
    INVALID_STREAM,
    REFUSED_STREAM,
    UNSUPPORTED_VERSION,
    CANCEL,
    INTERNAL_ERROR,
    FLOW_CONTROL_ERROR,
    STREAM_IN_USE,
    STREAM_ALREADY_CLOSED,
    INVALID_CREDENTIALS,
    FRAME_TOO_LARGE,
    INVALID_UPPER_BOUND /* Invalid value, upper bound for enum. */
} spdy_rst_stream_status_t;

static const char *rst_stream_status_names[] = {
    "INVALID",
    "PROTOCOL_ERROR",
    "INVALID_STREAM",
    "REFUSED_STREAM",
    "UNSUPPORTED_VERSION",
    "CANCEL",
    "INTERNAL_ERROR",
    "FLOW_CONTROL_ERROR",
    "STREAM_IN_USE",
    "STREAM_ALREADY_CLOSED",
    "INVALID_CREDENTIALS",
    "FRAME_TOO_LARGE",
    "INVALID"
};

/*
 * This structure will be tied to each SPDY frame.
 * Note that there may be multiple SPDY frames
 * in one packet.
 */
typedef struct _spdy_frame_info_t {
    guint32 stream_id;
    guint8 *header_block;
    guint   header_block_len;
    guint16 frame_type;
} spdy_frame_info_t;

/*
 * This structures keeps track of all the data frames
 * associated with a stream, so that they can be
 * reassembled into a single chunk.
 */
typedef struct _spdy_data_frame_t {
    guint8 *data;
    guint32 length;
    guint32 framenum;
} spdy_data_frame_t;

typedef struct _spdy_stream_info_t {
    gchar *content_type;
    gchar *content_type_parameters;
    gchar *content_encoding;
    GSList *data_frames;
    tvbuff_t *assembled_data;
    guint num_data_frames;
} spdy_stream_info_t;

#include <epan/tap.h>

/* Handles for metadata population. */

static int spdy_tap = -1;
static int spdy_eo_tap = -1;

static int proto_spdy = -1;
static int hf_spdy_syn_stream = -1;
static int hf_spdy_syn_reply = -1;
static int hf_spdy_headers = -1;
static int hf_spdy_data = -1;
static int hf_spdy_control_bit = -1;
static int hf_spdy_version = -1;
static int hf_spdy_type = -1;
static int hf_spdy_flags = -1;
static int hf_spdy_flags_fin = -1;
static int hf_spdy_length = -1;
static int hf_spdy_header = -1;
static int hf_spdy_header_name = -1;
static int hf_spdy_header_value = -1;
static int hf_spdy_streamid = -1;
static int hf_spdy_associated_streamid = -1;
static int hf_spdy_priority = -1;
static int hf_spdy_num_headers = -1;
static int hf_spdy_num_headers_string = -1;

static gint ett_spdy = -1;
static gint ett_spdy_syn_stream = -1;
static gint ett_spdy_syn_reply = -1;
static gint ett_spdy_fin_stream = -1;
static gint ett_spdy_flags = -1;
static gint ett_spdy_header = -1;
static gint ett_spdy_header_name = -1;
static gint ett_spdy_header_value = -1;

static gint ett_spdy_encoded_entity = -1;

static dissector_handle_t data_handle;
static dissector_handle_t media_handle;
static dissector_handle_t spdy_handle;

/* Stuff for generation/handling of fields for custom HTTP headers */
typedef struct _header_field_t {
        gchar* header_name;
        gchar* header_desc;
} header_field_t;

static gboolean spdy_assemble_entity_bodies = TRUE;

/*
 * Decompression of zlib encoded entities.
 */
#ifdef HAVE_LIBZ
static gboolean spdy_decompress_body = TRUE;
static gboolean spdy_decompress_headers = TRUE;
#else
static gboolean spdy_decompress_body = FALSE;
static gboolean spdy_decompress_headers = FALSE;
#endif
static gboolean spdy_debug = FALSE;

static const value_string vals_status_code[] = {
    { 100, "Continue" },
    { 101, "Switching Protocols" },
    { 102, "Processing" },
    { 199, "Informational - Others" },

    { 200, "OK"},
    { 201, "Created"},
    { 202, "Accepted"},
    { 203, "Non-authoritative Information"},
    { 204, "No Content"},
    { 205, "Reset Content"},
    { 206, "Partial Content"},
    { 207, "Multi-Status"},
    { 299, "Success - Others"},

    { 300, "Multiple Choices"},
    { 301, "Moved Permanently"},
    { 302, "Found"},
    { 303, "See Other"},
    { 304, "Not Modified"},
    { 305, "Use Proxy"},
    { 307, "Temporary Redirect"},
    { 399, "Redirection - Others"},

    { 400, "Bad Request"},
    { 401, "Unauthorized"},
    { 402, "Payment Required"},
    { 403, "Forbidden"},
    { 404, "Not Found"},
    { 405, "Method Not Allowed"},
    { 406, "Not Acceptable"},
    { 407, "Proxy Authentication Required"},
    { 408, "Request Time-out"},
    { 409, "Conflict"},
    { 410, "Gone"},
    { 411, "Length Required"},
    { 412, "Precondition Failed"},
    { 413, "Request Entity Too Large"},
    { 414, "Request-URI Too Long"},
    { 415, "Unsupported Media Type"},
    { 416, "Requested Range Not Satisfiable"},
    { 417, "Expectation Failed"},
    { 418, "I'm a teapot"},         /* RFC 2324 */
    { 422, "Unprocessable Entity"},
    { 423, "Locked"},
    { 424, "Failed Dependency"},
    { 499, "Client Error - Others"},

    { 500, "Internal Server Error"},
    { 501, "Not Implemented"},
    { 502, "Bad Gateway"},
    { 503, "Service Unavailable"},
    { 504, "Gateway Time-out"},
    { 505, "HTTP Version not supported"},
    { 507, "Insufficient Storage"},
    { 599, "Server Error - Others"},

    { 0,    NULL}
};

static const char spdy_dictionary[] = {
  0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69,  // - - - - o p t i
  0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68,  // o n s - - - - h
  0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70,  // e a d - - - - p
  0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70,  // o s t - - - - p
  0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65,  // u t - - - - d e
  0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05,  // l e t e - - - -
  0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00,  // t r a c e - - -
  0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00,  // - a c c e p t -
  0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70,  // - - - a c c e p
  0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,  // t - c h a r s e
  0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63,  // t - - - - a c c
  0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,  // e p t - e n c o
  0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f,  // d i n g - - - -
  0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c,  // a c c e p t - l
  0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00,  // a n g u a g e -
  0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70,  // - - - a c c e p
  0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73,  // t - r a n g e s
  0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00,  // - - - - a g e -
  0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77,  // - - - a l l o w
  0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68,  // - - - - a u t h
  0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,  // o r i z a t i o
  0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63,  // n - - - - c a c
  0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72,  // h e - c o n t r
  0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f,  // o l - - - - c o
  0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,  // n n e c t i o n
  0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74,  // - - - - c o n t
  0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65,  // e n t - b a s e
  0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74,  // - - - - c o n t
  0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,  // e n t - e n c o
  0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10,  // d i n g - - - -
  0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,  // c o n t e n t -
  0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,  // l a n g u a g e
  0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74,  // - - - - c o n t
  0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67,  // e n t - l e n g
  0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f,  // t h - - - - c o
  0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f,  // n t e n t - l o
  0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00,  // c a t i o n - -
  0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,  // - - c o n t e n
  0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00,  // t - m d 5 - - -
  0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,  // - c o n t e n t
  0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00,  // - r a n g e - -
  0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,  // - - c o n t e n
  0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00,  // t - t y p e - -
  0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00,  // - - d a t e - -
  0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00,  // - - e t a g - -
  0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74,  // - - e x p e c t
  0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69,  // - - - - e x p i
  0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66,  // r e s - - - - f
  0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68,  // r o m - - - - h
  0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69,  // o s t - - - - i
  0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00,  // f - m a t c h -
  0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f,  // - - - i f - m o
  0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73,  // d i f i e d - s
  0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d,  // i n c e - - - -
  0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d,  // i f - n o n e -
  0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00,  // m a t c h - - -
  0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67,  // - i f - r a n g
  0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d,  // e - - - - i f -
  0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69,  // u n m o d i f i
  0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65,  // e d - s i n c e
  0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74,  // - - - - l a s t
  0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,  // - m o d i f i e
  0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63,  // d - - - - l o c
  0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,  // a t i o n - - -
  0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72,  // - m a x - f o r
  0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00,  // w a r d s - - -
  0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00,  // - p r a g m a -
  0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79,  // - - - p r o x y
  0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,  // - a u t h e n t
  0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00,  // i c a t e - - -
  0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61,  // - p r o x y - a
  0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,  // u t h o r i z a
  0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05,  // t i o n - - - -
  0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00,  // r a n g e - - -
  0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72,  // - r e f e r e r
  0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72,  // - - - - r e t r
  0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00,  // y - a f t e r -
  0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,  // - - - s e r v e
  0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00,  // r - - - - t e -
  0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c,  // - - - t r a i l
  0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72,  // e r - - - - t r
  0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65,  // a n s f e r - e
  0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,  // n c o d i n g -
  0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61,  // - - - u p g r a
  0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73,  // d e - - - - u s
  0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,  // e r - a g e n t
  0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79,  // - - - - v a r y
  0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00,  // - - - - v i a -
  0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69,  // - - - w a r n i
  0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77,  // n g - - - - w w
  0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,  // w - a u t h e n
  0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00,  // t i c a t e - -
  0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,  // - - m e t h o d
  0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00,  // - - - - g e t -
  0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,  // - - - s t a t u
  0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30,  // s - - - - 2 0 0
  0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76,  // - O K - - - - v
  0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00,  // e r s i o n - -
  0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,  // - - H T T P - 1
  0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72,  // - 1 - - - - u r
  0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62,  // l - - - - p u b
  0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73,  // l i c - - - - s
  0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69,  // e t - c o o k i
  0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65,  // e - - - - k e e
  0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00,  // p - a l i v e -
  0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69,  // - - - o r i g i
  0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32,  // n 1 0 0 1 0 1 2
  0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35,  // 0 1 2 0 2 2 0 5
  0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30,  // 2 0 6 3 0 0 3 0
  0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33,  // 2 3 0 3 3 0 4 3
  0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37,  // 0 5 3 0 6 3 0 7
  0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30,  // 4 0 2 4 0 5 4 0
  0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34,  // 6 4 0 7 4 0 8 4
  0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31,  // 0 9 4 1 0 4 1 1
  0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31,  // 4 1 2 4 1 3 4 1
  0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34,  // 4 4 1 5 4 1 6 4
  0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34,  // 1 7 5 0 2 5 0 4
  0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e,  // 5 0 5 2 0 3 - N
  0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f,  // o n - A u t h o
  0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65,  // r i t a t i v e
  0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61,  // - I n f o r m a
  0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20,  // t i o n 2 0 4 -
  0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65,  // N o - C o n t e
  0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f,  // n t 3 0 1 - M o
  0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d,  // v e d - P e r m
  0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34,  // a n e n t l y 4
  0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52,  // 0 0 - B a d - R
  0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30,  // e q u e s t 4 0
  0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68,  // 1 - U n a u t h
  0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30,  // o r i z e d 4 0
  0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64,  // 3 - F o r b i d
  0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e,  // d e n 4 0 4 - N
  0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64,  // o t - F o u n d
  0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65,  // 5 0 0 - I n t e
  0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72,  // r n a l - S e r
  0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f,  // v e r - E r r o
  0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74,  // r 5 0 1 - N o t
  0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,  // - I m p l e m e
  0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20,  // n t e d 5 0 3 -
  0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20,  // S e r v i c e -
  0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61,  // U n a v a i l a
  0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46,  // b l e J a n - F
  0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41,  // e b - M a r - A
  0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a,  // p r - M a y - J
  0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41,  // u n - J u l - A
  0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20,  // u g - S e p t -
  0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20,  // O c t - N o v -
  0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30,  // D e c - 0 0 - 0
  0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e,  // 0 - 0 0 - M o n
  0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57,  // - - T u e - - W
  0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c,  // e d - - T h u -
  0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61,  // - F r i - - S a
  0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,  // t - - S u n - -
  0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b,  // G M T c h u n k
  0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f,  // e d - t e x t -
  0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61,  // h t m l - i m a
  0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69,  // g e - p n g - i
  0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67,  // m a g e - j p g
  0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67,  // - i m a g e - g
  0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,  // i f - a p p l i
  0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,  // c a t i o n - x
  0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,  // m l - a p p l i
  0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,  // c a t i o n - x
  0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c,  // h t m l - x m l
  0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c,  // - t e x t - p l
  0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74,  // a i n - t e x t
  0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72,  // - j a v a s c r
  0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c,  // i p t - p u b l
  0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,  // i c p r i v a t
  0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65,  // e m a x - a g e
  0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65,  // - g z i p - d e
  0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64,  // f l a t e - s d
  0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,  // c h c h a r s e
  0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63,  // t - u t f - 8 c
  0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69,  // h a r s e t - i
  0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d,  // s o - 8 8 5 9 -
  0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a,  // 1 - u t f - - -
  0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e         // - e n q - 0 -
};

static void reset_decompressors(void) {
  if (spdy_debug) printf("Should reset SPDY decompressors\n");
}

/*
 * Returns conversation data for a given packet. If conversation data can't be
 * found, creates and returns new conversation data.
 */
static spdy_conv_t * get_or_create_spdy_conversation_data(packet_info *pinfo) {
  conversation_t  *conversation;
  spdy_conv_t *conv_data;
  int retcode;

  conversation = find_conversation(pinfo->fd->num,
                                   &pinfo->src,
                                   &pinfo->dst,
                                   pinfo->ptype,
                                   pinfo->srcport,
                                   pinfo->destport,
                                   0);

  if (!conversation)  /* Conversation does not exist yet - create it */
    conversation = conversation_new(pinfo->fd->num,
                                    &pinfo->src,
                                    &pinfo->dst,
                                    pinfo->ptype,
                                    pinfo->srcport,
                                    pinfo->destport,
                                    0);

  /* Retrieve information from conversation */
  conv_data = conversation_get_proto_data(conversation, proto_spdy);
  if (!conv_data) {
    /* Set up the conversation structure itself */
    conv_data = se_alloc0(sizeof(spdy_conv_t));

    conv_data->streams = NULL;
    if (spdy_decompress_headers) {
      conv_data->rqst_decompressor = se_alloc0(sizeof(z_stream));
      conv_data->rply_decompressor = se_alloc0(sizeof(z_stream));
      retcode = inflateInit(conv_data->rqst_decompressor);
      if (retcode == Z_OK) {
        retcode = inflateInit(conv_data->rply_decompressor);
      }
      if (retcode != Z_OK) {
        printf("frame #%d: inflateInit() failed: %d\n",
               pinfo->fd->num, retcode);
      } else if (spdy_debug) {
        printf("created decompressor\n");
      }
      conv_data->dictionary_id = adler32(0L, Z_NULL, 0);
      conv_data->dictionary_id = adler32(conv_data->dictionary_id,
                                         spdy_dictionary,
                                         sizeof(spdy_dictionary));
    }

    conversation_add_proto_data(conversation, proto_spdy, conv_data);
    register_postseq_cleanup_routine(reset_decompressors);
  }

  if (spdy_debug) {
    printf("\n===========================================\n\n");
    printf("Conversation for frame #%d is %p\n", pinfo->fd->num, conversation);
    if (conversation)
        printf("  conv_data=%p\n", conversation_get_proto_data(conversation, proto_spdy));
  }
  return conv_data;
}

/*
 * Retains state on a given stream.
 */
static void spdy_save_stream_info(spdy_conv_t *conv_data,
                                  guint32 stream_id,
                                  gchar *content_type,
                                  gchar *content_type_params,
                                  gchar *content_encoding) {
  spdy_stream_info_t *si;

  if (conv_data->streams == NULL) {
    conv_data->streams = g_array_new(FALSE, TRUE, sizeof(spdy_stream_info_t *));
  }
  if (stream_id < conv_data->streams->len) {
    DISSECTOR_ASSERT(g_array_index(conv_data->streams, spdy_stream_info_t*, stream_id) == NULL);
  } else {
    g_array_set_size(conv_data->streams, stream_id+1);
  }
  si = se_alloc(sizeof(spdy_stream_info_t));
  si->content_type = content_type;
  si->content_type_parameters = content_type_params;
  si->content_encoding = content_encoding;
  si->data_frames = NULL;
  si->num_data_frames = 0;
  si->assembled_data = NULL;
  g_array_index(conv_data->streams, spdy_stream_info_t*, stream_id) = si;
  if (spdy_debug) {
    printf("Saved stream info for ID %u, content type %s\n",
           stream_id, content_type);
  }
}

/*
 * Retrieves previously saved state on a given stream.
 */
static spdy_stream_info_t* spdy_get_stream_info(spdy_conv_t *conv_data,
                                                guint32 stream_id) {
    if (conv_data->streams == NULL || stream_id >= conv_data->streams->len) {
      return NULL;
    } else {
      return g_array_index(conv_data->streams, spdy_stream_info_t*, stream_id);
    }
}

/*
 * Adds a data chunk to a given SPDY converstaion/stream.
 */
static void spdy_add_data_chunk(spdy_conv_t *conv_data,
                                guint32 stream_id,
                                guint32 frame,
                                guint8 *data,
                                guint32 length) {
  spdy_stream_info_t *si = spdy_get_stream_info(conv_data, stream_id);

  if (si == NULL) {
    if (spdy_debug) {
      printf("No stream_info found for stream %d\n", stream_id);
    }
  } else {
    spdy_data_frame_t *df = g_malloc(sizeof(spdy_data_frame_t));
    df->data = data;
    df->length = length;
    df->framenum = frame;
    si->data_frames = g_slist_append(si->data_frames, df);
    ++si->num_data_frames;
    if (spdy_debug) {
      printf("Saved %u bytes of data for stream %u frame %u\n",
             length, stream_id, df->framenum);
    }
  }
}

/*
 * Increment the count of DATA frames found on a given stream.
 */
static void spdy_increment_data_chunk_count(spdy_conv_t *conv_data,
                                            guint32 stream_id) {
  spdy_stream_info_t *si = spdy_get_stream_info(conv_data, stream_id);
  if (si != NULL) {
    ++si->num_data_frames;
  }
}

/*
 * Return the number of data frames saved so far for the specified stream.
 */
static guint spdy_get_num_data_frames(spdy_conv_t *conv_data,
                                      guint32 stream_id) {
  spdy_stream_info_t *si = spdy_get_stream_info(conv_data, stream_id);

  return si == NULL ? 0 : si->num_data_frames;
}

/*
 * Reassembles DATA frames for a given stream into one tvb.
 */
static spdy_stream_info_t* spdy_assemble_data_frames(spdy_conv_t *conv_data,
                                                     guint32 stream_id) {
  spdy_stream_info_t *si = spdy_get_stream_info(conv_data, stream_id);
  tvbuff_t *tvb;

  if (si == NULL) {
    return NULL;
  }

  /*
   * Compute the total amount of data and concatenate the
   * data chunks, if it hasn't already been done.
   */
  if (si->assembled_data == NULL) {
    spdy_data_frame_t *df;
    guint8 *data;
    guint32 datalen;
    guint32 offset;
    guint32 framenum;
    GSList *dflist = si->data_frames;
    if (dflist == NULL) {
      return si;
    }
    datalen = 0;
    /*
     * It'd be nice to use a composite tvbuff here, but since
     * only a real-data tvbuff can be the child of another
     * tvb, we can't. It would be nice if this limitation
     * could be fixed.
     */
    while (dflist != NULL) {
      df = dflist->data;
      datalen += df->length;
      dflist = g_slist_next(dflist);
    }
    if (datalen != 0) {
      data = se_alloc(datalen);
      dflist = si->data_frames;
      offset = 0;
      framenum = 0;
      while (dflist != NULL) {
        df = dflist->data;
        memcpy(data+offset, df->data, df->length);
        offset += df->length;
        dflist = g_slist_next(dflist);
      }
      tvb = tvb_new_real_data(data, datalen, datalen);
      si->assembled_data = tvb;
    }
  }
  return si;
}

/*
 * Cleans up data frames accounted for by a given stream.
 */
static void spdy_discard_data_frames(spdy_stream_info_t *si) {
  GSList *dflist = si->data_frames;
  spdy_data_frame_t *df;

  if (dflist == NULL) {
    return;
  }
  while (dflist != NULL) {
    df = dflist->data;
    if (df->data != NULL) {
      g_free(df->data);
      df->data = NULL;
    }
    dflist = g_slist_next(dflist);
  }
  /*
  TODO(hkhalil): Why was this commented out?
  g_slist_free(si->data_frames);
  si->data_frames = NULL;
  */
}

/* TODO(cbentzel): tvb_child_uncompress should be exported by wireshark. */
static tvbuff_t* spdy_tvb_child_uncompress(tvbuff_t *parent _U_, tvbuff_t *tvb,
                                           int offset, int comprlen) {
  tvbuff_t *new_tvb = tvb_uncompress(tvb, offset, comprlen);
  if (new_tvb) {
    tvb_set_child_real_data_tvbuff (parent, new_tvb);
  }
  return new_tvb;
}

/*
 * Performs DATA frame dissection.
 */
static int dissect_spdy_data_frame(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo,
                                   proto_tree *top_level_tree,
                                   proto_tree *spdy_tree,
                                   proto_item *spdy_proto,
                                   spdy_conv_t *conv_data) {
  guint32 stream_id;
  guint8 flags;
  guint32 frame_length;
  proto_item *ti;
  proto_tree *flags_tree;
  guint32 reported_datalen;
  guint32 datalen;
  dissector_table_t media_type_subdissector_table;
  dissector_table_t port_subdissector_table;
  dissector_handle_t handle;
  guint num_data_frames;
  gboolean dissected;

  stream_id = tvb_get_bits32(tvb, (offset << 3) + 1, 31, FALSE);
  flags = tvb_get_guint8(tvb, offset+4);
  frame_length = tvb_get_ntoh24(tvb, offset+5);

  if (spdy_debug) {
    printf("Data frame [stream_id=%u flags=0x%x length=%d]\n",
           stream_id, flags, frame_length);
  }
  if (spdy_tree) {
    proto_item_append_text(spdy_tree, ", data frame");
  }
  col_add_fstr(pinfo->cinfo, COL_INFO, "DATA[%u] length=%d",
               stream_id, frame_length);

  proto_item_append_text(spdy_proto, ":%s stream=%d length=%d",
                         flags & SPDY_FIN ? " [FIN]" : "", stream_id,
                         frame_length);

  proto_tree_add_boolean(spdy_tree, hf_spdy_control_bit, tvb, offset, 1, 0);
  proto_tree_add_item(spdy_tree,
                      hf_spdy_streamid,
                      tvb,
                      offset,
                      4,
                      ENC_BIG_ENDIAN);
  proto_tree_add_bytes(spdy_tree, hf_spdy_data, tvb, offset + 8, frame_length,
                       "Some Arbitrary Data"); /* TODO(hkhalil): Improve. */
  ti = proto_tree_add_uint_format(spdy_tree, hf_spdy_flags, tvb, offset+4, 1,
                                  flags, "Flags: 0x%02x%s", flags,
                                  flags&SPDY_FIN ? " (FIN)" : "");

  flags_tree = proto_item_add_subtree(ti, ett_spdy_flags);
  proto_tree_add_boolean(flags_tree, hf_spdy_flags_fin, tvb, offset + 4, 1,
                         flags);
  proto_tree_add_item(spdy_tree,
                      hf_spdy_length,
                      tvb,
                      offset + 5,
                      3,
                      ENC_BIG_ENDIAN);

  datalen = tvb_length_remaining(tvb, offset);
  if (datalen > frame_length) {
    datalen = frame_length;
  }

  reported_datalen = tvb_reported_length_remaining(tvb, offset);
  if (reported_datalen > frame_length) {
    reported_datalen = frame_length;
  }

  num_data_frames = spdy_get_num_data_frames(conv_data, stream_id);
  if (datalen != 0 || num_data_frames != 0) {
    /*
     * There's stuff left over; process it.
     */
    tvbuff_t *next_tvb = NULL;
    tvbuff_t    *data_tvb = NULL;
    spdy_stream_info_t *si = NULL;
    void *save_private_data = NULL;
    guint8 *copied_data;
    gboolean private_data_changed = FALSE;
    gboolean is_single_chunk = FALSE;
    gboolean have_entire_body;

    /*
     * Create a tvbuff for the payload.
     */
    if (datalen != 0) {
      next_tvb = tvb_new_subset(tvb, offset+8, datalen,
                                reported_datalen);
      is_single_chunk = num_data_frames == 0 && (flags & SPDY_FIN) != 0;
      if (!pinfo->fd->flags.visited) {
        if (!is_single_chunk) {
          if (spdy_assemble_entity_bodies) {
            copied_data = tvb_memdup(next_tvb, 0, datalen);
            spdy_add_data_chunk(conv_data, stream_id, pinfo->fd->num,
                                copied_data, datalen);
          } else {
            spdy_increment_data_chunk_count(conv_data, stream_id);
          }
        }
      }
    } else {
      is_single_chunk = (num_data_frames == 1);
    }

    if (!(flags & SPDY_FIN)) {
      col_set_fence(pinfo->cinfo, COL_INFO);
      col_add_fstr(pinfo->cinfo, COL_INFO, " (partial entity)");
      proto_item_append_text(spdy_proto, " (partial entity body)");
      /* would like the proto item to say */
      /* " (entity body fragment N of M)" */
      goto body_dissected;
    }
    have_entire_body = is_single_chunk;
    /*
     * On seeing the last data frame in a stream, we can
     * reassemble the frames into one data block.
     */
    si = spdy_assemble_data_frames(conv_data, stream_id);
    if (si == NULL) {
      goto body_dissected;
    }
    data_tvb = si->assembled_data;
    if (spdy_assemble_entity_bodies) {
      have_entire_body = TRUE;
    }

    if (!have_entire_body) {
      goto body_dissected;
    }

    if (data_tvb == NULL) {
      data_tvb = next_tvb;
    } else {
      add_new_data_source(pinfo, data_tvb, "Assembled entity body");
    }

    if (have_entire_body && si->content_encoding != NULL &&
        g_ascii_strcasecmp(si->content_encoding, "identity") != 0) {
      /*
       * We currently can't handle, for example, "compress";
       * just handle them as data for now.
       *
       * After July 7, 2004 the LZW patent expires, so support
       * might be added then.  However, I don't think that
       * anybody ever really implemented "compress", due to
       * the aforementioned patent.
       */
      tvbuff_t *uncomp_tvb = NULL;
      proto_item *e_ti = NULL;
      proto_item *ce_ti = NULL;
      proto_tree *e_tree = NULL;

      if (spdy_decompress_body &&
          (g_ascii_strcasecmp(si->content_encoding, "gzip") == 0 ||
           g_ascii_strcasecmp(si->content_encoding, "deflate") == 0)) {
        uncomp_tvb = spdy_tvb_child_uncompress(tvb, data_tvb, 0,
                                               tvb_length(data_tvb));
      }
      /*
       * Add the encoded entity to the protocol tree
       */
      e_ti = proto_tree_add_text(top_level_tree, data_tvb,
                                 0, tvb_length(data_tvb),
                                 "Content-encoded entity body (%s): %u bytes",
                                 si->content_encoding,
                                 tvb_length(data_tvb));
      e_tree = proto_item_add_subtree(e_ti, ett_spdy_encoded_entity);
      if (si->num_data_frames > 1) {
        GSList *dflist;
        spdy_data_frame_t *df;
        guint32 framenum;
        ce_ti = proto_tree_add_text(e_tree, data_tvb, 0,
                                    tvb_length(data_tvb),
                                    "Assembled from %d frames in packet(s)",
                                    si->num_data_frames);
        dflist = si->data_frames;
        framenum = 0;
        while (dflist != NULL) {
          df = dflist->data;
          if (framenum != df->framenum) {
            proto_item_append_text(ce_ti, " #%u", df->framenum);
            framenum = df->framenum;
          }
          dflist = g_slist_next(dflist);
        }
      }

      if (uncomp_tvb != NULL) {
        /*
         * Decompression worked
         */

        /* XXX - Don't free this, since it's possible
         * that the data was only partially
         * decompressed, such as when desegmentation
         * isn't enabled.
         *
         tvb_free(next_tvb);
         */
        proto_item_append_text(e_ti, " -> %u bytes", tvb_length(uncomp_tvb));
        data_tvb = uncomp_tvb;
        add_new_data_source(pinfo, data_tvb, "Uncompressed entity body");
      } else {
        if (spdy_decompress_body) {
          proto_item_append_text(e_ti, " [Error: Decompression failed]");
        }
        call_dissector(data_handle, data_tvb, pinfo, e_tree);

        goto body_dissected;
      }
    }
    if (si != NULL) {
      spdy_discard_data_frames(si);
    }
    /*
     * Do subdissector checks.
     *
     * First, check whether some subdissector asked that they
     * be called if something was on some particular port.
     */

    port_subdissector_table = find_dissector_table("http.port");
    media_type_subdissector_table = find_dissector_table("media_type");
    if (have_entire_body && port_subdissector_table != NULL) {
      handle = dissector_get_port_handle(port_subdissector_table,
                                         pinfo->match_port);
    } else {
      handle = NULL;
    }
    if (handle == NULL && have_entire_body && si->content_type != NULL &&
      media_type_subdissector_table != NULL) {
      /*
       * We didn't find any subdissector that
       * registered for the port, and we have a
       * Content-Type value.  Is there any subdissector
       * for that content type?
       */
      save_private_data = pinfo->private_data;
      private_data_changed = TRUE;

      if (si->content_type_parameters) {
        pinfo->private_data = ep_strdup(si->content_type_parameters);
      } else {
        pinfo->private_data = NULL;
      }
      /*
       * Calling the string handle for the media type
       * dissector table will set pinfo->match_string
       * to si->content_type for us.
       */
      pinfo->match_string = si->content_type;
      handle = dissector_get_string_handle(media_type_subdissector_table,
                                           si->content_type);
    }
    if (handle != NULL) {
      /*
       * We have a subdissector - call it.
       */
      dissected = call_dissector(handle, data_tvb, pinfo, top_level_tree);
    } else {
      dissected = FALSE;
    }

    if (dissected) {
      /*
       * The subdissector dissected the body.
       * Fix up the top-level item so that it doesn't
       * include the stuff for that protocol.
       */
      if (ti != NULL) {
        proto_item_set_len(ti, offset);
      }
    } else if (have_entire_body && si->content_type != NULL) {
      /*
       * Calling the default media handle if there is a content-type that
       * wasn't handled above.
       */
      call_dissector(media_handle, next_tvb, pinfo, top_level_tree);
    } else {
      /* Call the default data dissector */
      call_dissector(data_handle, next_tvb, pinfo, top_level_tree);
    }

body_dissected:
    /*
     * Do *not* attempt at freeing the private data;
     * it may be in use by subdissectors.
     */
    if (private_data_changed) { /*restore even NULL value*/
        pinfo->private_data = save_private_data;
    }
    /*
     * We've processed "datalen" bytes worth of data
     * (which may be no data at all); advance the
     * offset past whatever data we've processed.
     */
  }
  return frame_length + 8;
}

/*
 * Performs header decompression.
 */
static guint8* spdy_decompress_header_block(tvbuff_t *tvb,
                                            z_streamp decomp,
                                            guint32 dictionary_id,
                                            int offset,
                                            guint32 length,
                                            guint *uncomp_length) {
  int retcode;
  size_t bufsize = 16384;
  const guint8 *hptr = tvb_get_ptr(tvb, offset, length);
  guint8 *uncomp_block = ep_alloc(bufsize);
  decomp->next_in = (Bytef *)hptr;
  decomp->avail_in = length;
  decomp->next_out = uncomp_block;
  decomp->avail_out = bufsize;
  retcode = inflate(decomp, Z_SYNC_FLUSH);
  if (retcode == Z_NEED_DICT) {
    if (decomp->adler != dictionary_id) {
      printf("decompressor wants dictionary %#x, but we have %#x\n",
             (guint)decomp->adler, dictionary_id);
    }/* else*/ {
      retcode = inflateSetDictionary(decomp,
                                     spdy_dictionary,
                                     sizeof(spdy_dictionary));
      if (retcode == Z_OK) {
        retcode = inflate(decomp, Z_SYNC_FLUSH);
      }
    }
  }

  if (retcode != Z_OK) {
    return NULL;
  } else {
    *uncomp_length = bufsize - decomp->avail_out;
    if (spdy_debug) {
      printf("Inflation SUCCEEDED. uncompressed size=%d\n", *uncomp_length);
    }
    if (decomp->avail_in != 0) {
      if (spdy_debug) {
        printf("  but there were %d input bytes left over\n", decomp->avail_in);
      }
    }
  }
  return se_memdup(uncomp_block, *uncomp_length);
}

/*
 * Try to determine heuristically whether the header block is
 * compressed. For an uncompressed block, the first two bytes
 * gives the number of headers. Each header name and value is
 * a two-byte length followed by ASCII characters.
 */
static gboolean spdy_check_header_compression(tvbuff_t *tvb,
                                              int offset,
                                              guint32 frame_length) {
  guint16 length;
  if (!tvb_bytes_exist(tvb, offset, 6)) {
    return 1;
  }
  length = tvb_get_ntohs(tvb, offset);
  if (length > frame_length) {
    return 1;
  }
  length = tvb_get_ntohs(tvb, offset+2);
  if (length > frame_length) {
    return 1;
  }
  if (spdy_debug) printf("Looks like the header block is not compressed\n");
  return 0;
}

/* TODO(cbentzel): Change wireshark to export p_remove_proto_data, rather
 * than duplicating code here. */
typedef struct _spdy_frame_proto_data {
  int proto;
  void *proto_data;
} spdy_frame_proto_data;

static gint spdy_p_compare(gconstpointer a, gconstpointer b)
{
  const spdy_frame_proto_data *ap = (const spdy_frame_proto_data *)a;
  const spdy_frame_proto_data *bp = (const spdy_frame_proto_data *)b;

  if (ap -> proto > bp -> proto) {
    return 1;
  } else if (ap -> proto == bp -> proto) {
    return 0;
  } else {
    return -1;
  }
}

static void spdy_p_remove_proto_data(frame_data *fd, int proto) {
  spdy_frame_proto_data temp;
  GSList *item;

  temp.proto = proto;
  temp.proto_data = NULL;

  item = g_slist_find_custom(fd->pfd, (gpointer *)&temp, spdy_p_compare);

  if (item) {
    fd->pfd = g_slist_remove(fd->pfd, item->data);
  }
}

/*
 * Saves state on header data for a given stream.
 */
static spdy_frame_info_t * spdy_save_header_block(frame_data *fd,
                                                  guint32 stream_id,
                                                  guint frame_type,
                                                  guint8 *header,
                                                  guint length) {
  GSList *filist = p_get_proto_data(fd, proto_spdy);
  spdy_frame_info_t *frame_info = se_alloc(sizeof(spdy_frame_info_t));
  if (filist != NULL)
    spdy_p_remove_proto_data(fd, proto_spdy);
  frame_info->stream_id = stream_id;
  frame_info->header_block = header;
  frame_info->header_block_len = length;
  frame_info->frame_type = frame_type;
  filist = g_slist_append(filist, frame_info);
  p_add_proto_data(fd, proto_spdy, filist);
  return frame_info;
  /* TODO(ers) these need to get deleted when no longer needed */
}

/*
 * Retrieves saved state for a given stream.
 */
static spdy_frame_info_t* spdy_find_saved_header_block(frame_data *fd,
                                                       guint32 stream_id,
                                                       guint16 frame_type) {
  GSList *filist = p_get_proto_data(fd, proto_spdy);
  while (filist != NULL) {
      spdy_frame_info_t *fi = filist->data;
      if (fi->stream_id == stream_id && fi->frame_type == frame_type)
          return fi;
      filist = g_slist_next(filist);
  }
  return NULL;
}

/*
 * Given a content type string that may contain optional parameters,
 * return the parameter string, if any, otherwise return NULL. This
 * also has the side effect of null terminating the content type
 * part of the original string.
 */
static gchar* spdy_parse_content_type(gchar *content_type) {
  gchar *cp = content_type;

  while (*cp != '\0' && *cp != ';' && !isspace(*cp)) {
    *cp = tolower(*cp);
    ++cp;
  }
  if (*cp == '\0') {
    cp = NULL;
  }

  if (cp != NULL) {
    *cp++ = '\0';
    while (*cp == ';' || isspace(*cp)) {
      ++cp;
    }
    if (*cp != '\0') {
      return cp;
    }
  }
  return NULL;
}

/*
 * Performs SPDY frame dissection.
 * TODO(hkhalil): Refactor!
 */
int dissect_spdy_frame(tvbuff_t *tvb, int offset, packet_info *pinfo,
                              proto_tree *tree, spdy_conv_t *conv_data) {
  guint8              control_bit;
  guint16             version = 0;
  guint16             frame_type;
  guint8              flags;
  guint32             frame_length;
  guint32             stream_id = 0;
  guint32             associated_stream_id = 0;
  gint                priority = 0;
  guint32             num_headers;
  guint32             rst_status;
  guint32             ping_id;
  guint32             window_update_delta;
  guint8              *frame_header = NULL;
  const char          *proto_tag;
  const char          *frame_type_name;
  proto_tree          *spdy_tree = NULL;
  proto_item          *ti = NULL;
  proto_item          *spdy_proto = NULL;
  int                 orig_offset;
  int                 hdr_offset = 0;
  proto_tree          *sub_tree = NULL;
  proto_tree          *flags_tree;
  tvbuff_t            *header_tvb = NULL;
  gboolean            headers_compressed;
  gchar               *hdr_verb = NULL;
  gchar               *hdr_url = NULL;
  gchar               *hdr_version = NULL;
  gchar               *content_type = NULL;
  gchar               *content_encoding = NULL;

  if (spdy_debug) {
    printf("\n===========================================\n\n");
    printf("Attempting dissection for frame #%d\n",
           pinfo->fd->num);
  }

  /*
   * Minimum size for a SPDY frame is 8 bytes.
   */
  if (tvb_reported_length_remaining(tvb, offset) < 8) {
    if (spdy_debug) {
      printf("Reported length remaining too small (%d < 8)\n",
             tvb_reported_length_remaining(tvb, offset));
    }
    return -1;
  }

  proto_tag = "SPDY";
  col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_tag);

  /*
   * Is this a control frame or a data frame?
   */
  orig_offset = offset;
  control_bit = tvb_get_bits8(tvb, offset << 3, 1);
  if (control_bit) {
    /* Extract version and type. */
    version = tvb_get_bits16(tvb, (offset << 3) + 1, 15, FALSE);
    frame_type = tvb_get_ntohs(tvb, offset + 2);
    if (frame_type >= SPDY_INVALID) {
      if (spdy_debug) {
        printf("Invalid SPDY control frame type: %d\n", frame_type);
      }
      return -1;
    }
    frame_header = ep_tvb_memdup(tvb, offset, 8);
  } else {
    frame_type = SPDY_DATA;
  }
  frame_type_name = frame_type_names[frame_type];
  offset += 4;

  /* Extract flags and length. */
  flags = tvb_get_guint8(tvb, offset);
  frame_length = tvb_get_ntoh24(tvb, offset + 1);
  offset += 4;

  /*
   * Make sure there's as much data as the frame header says there is.
   */
  if ((guint)tvb_reported_length_remaining(tvb, offset) < frame_length) {
    if (spdy_debug) {
      printf("Not enough frame data: %d vs. %d\n",
              frame_length, tvb_reported_length_remaining(tvb, offset));
    }
    return -1;
  }

  /* Create SPDY tree elements. */
  if (tree) {
    spdy_proto = proto_tree_add_item(tree, proto_spdy, tvb, orig_offset,
                                     frame_length+8, FALSE);
    spdy_tree = proto_item_add_subtree(spdy_proto, ett_spdy);
  }

  if (control_bit) {
    if (spdy_debug) {
        printf("Control frame [version=%d type=%d flags=0x%x length=%d]\n",
                version, frame_type, flags, frame_length);
    }
    if (tree) {
      proto_item_append_text(spdy_tree, ", control frame");
    }
  } else {
    return dissect_spdy_data_frame(tvb, orig_offset, pinfo, tree,
                                   spdy_tree, spdy_proto, conv_data);
  }

  /* Add frame info. */
  col_add_str(pinfo->cinfo, COL_INFO, frame_type_name);

  num_headers = 0;
  switch (frame_type) {
    case SPDY_SYN_STREAM:
    case SPDY_SYN_REPLY:
    case SPDY_HEADERS:
      /* Set up bytes in tree. */
      if (tree) {
        int hf;
        if (frame_type == SPDY_SYN_STREAM) {
          hf = hf_spdy_syn_stream;
        } else if (frame_type == SPDY_SYN_REPLY) {
          hf = hf_spdy_syn_reply;
        } else {
          hf = hf_spdy_headers;
        }
        ti = proto_tree_add_bytes(spdy_tree, hf, tvb,
                                  orig_offset, 8, frame_header);
        sub_tree = proto_item_add_subtree(ti, ett_spdy_syn_stream);
      }

      /* Get stream id. */
      stream_id = tvb_get_bits32(tvb, (offset << 3) + 1, 31, FALSE);
      offset += 4;

      /* Get SYN_STREAM-only fields. */
      if (frame_type == SPDY_SYN_STREAM) {
        associated_stream_id = tvb_get_bits32(tvb, (offset << 3) + 1, 31,
                                              FALSE);
        offset += 4;
        priority = tvb_get_bits8(tvb, offset << 3, 3);
        offset += 2;
      }

      /* Add to info column. */
      col_append_fstr(pinfo->cinfo, COL_INFO, "[%u]", stream_id);

      /* Populate tree. */
      if (tree) {
        /* Add control bit. */
        proto_tree_add_bits_item(sub_tree,
                                 hf_spdy_control_bit,
                                 tvb,
                                 orig_offset * 8,
                                 1,
                                 ENC_NA);

        /* Add version. */
        proto_tree_add_bits_item(sub_tree,
                                 hf_spdy_version,
                                 tvb,
                                 orig_offset * 8 + 1,
                                 15,
                                 ENC_BIG_ENDIAN);

        /* Add control frame type. */
        proto_tree_add_item(sub_tree,
                            hf_spdy_type,
                            tvb,
                            orig_offset + 2,
                            2,
                            ENC_BIG_ENDIAN);

        /* Add flags. */
        ti = proto_tree_add_uint_format(sub_tree, hf_spdy_flags, tvb,
                                        orig_offset+4, 1, flags,
                                        "Flags: 0x%02x%s", flags,
                                        flags&SPDY_FIN ? " (FIN)" : "");
        flags_tree = proto_item_add_subtree(ti, ett_spdy_flags);
        proto_tree_add_boolean(flags_tree, hf_spdy_flags_fin, tvb,
                               orig_offset+4, 1, flags);

        /* Add length. */
        proto_tree_add_item(sub_tree,
                            hf_spdy_length,
                            tvb,
                            orig_offset+5,
                            3,
                            ENC_BIG_ENDIAN);

        /* Add stream ID. */
        proto_tree_add_item(sub_tree,
                            hf_spdy_streamid,
                            tvb,
                            orig_offset + 8,
                            4,
                            ENC_BIG_ENDIAN);

        /* Add fields specific to SYN_STREAM. */
        if (frame_type == SPDY_SYN_STREAM) {
          /* Add associated stream ID. */
          proto_tree_add_item(sub_tree,
                              hf_spdy_associated_streamid,
                              tvb,
                              orig_offset + 12,
                              4,
                              ENC_BIG_ENDIAN);

          /* Add priority. */
          proto_tree_add_item(sub_tree,
                              hf_spdy_priority,
                              tvb,
                              orig_offset + 16,
                              3,
                              ENC_BIG_ENDIAN);
        }
        proto_item_append_text(spdy_proto, ": %s%s stream=%d length=%d",
                               frame_type_name,
                               flags & SPDY_FIN ? " [FIN]" : "",
                               stream_id, frame_length);
        if (spdy_debug) {
          printf("  stream ID=%u priority=%d\n", stream_id, priority);
        }
      }
      break;

    case SPDY_RST_STREAM:
      /* Get stream ID and add to info column. */
      stream_id = tvb_get_bits32(tvb, (offset << 3) + 1, 31, FALSE);
      col_append_fstr(pinfo->cinfo, COL_INFO, "[%d]", stream_id);

      rst_status = tvb_get_ntohl(tvb, offset);
      if (rst_status >= INVALID_UPPER_BOUND ||
          rst_status <= INVALID_LOWER_BOUND) {
        /* Handle boundary conditions. */
        if (spdy_debug) {
          printf("Invalid status code for RST_STREAM: %u", rst_status);
        }
      } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
                        rst_stream_status_names[rst_status]);
      }
      offset += 8;
      break;

    case SPDY_SETTINGS:
      /* TODO(ers) fill in tree and summary */
      break;

    case SPDY_NOOP:
      break;

    case SPDY_PING:
      ping_id = tvb_get_ntohl(tvb, offset);
      offset += 4;
      col_append_fstr(pinfo->cinfo, COL_INFO, " ID=%u", ping_id);
      if (spdy_debug) {
        printf("Got PING ID %d", ping_id);
      }
      break;

    case SPDY_GOAWAY:
      /* TODO(hkhalil): Show last-good-stream-ID (31 bits). */
      /* TODO(hkhalil): Show status code (32 bits). */
      break;

    case SPDY_WINDOW_UPDATE:
      /* Get stream ID. */
      stream_id = tvb_get_bits32(tvb, (offset << 3) + 1, 31, FALSE);
      offset += 4;

      /* Get window update delta. */
      window_update_delta = tvb_get_bits32(tvb, (offset << 3) + 1, 31, FALSE);
      offset += 4;

      /* Add to info column. */
      col_append_fstr(pinfo->cinfo, COL_INFO, "[%u] Delta=%u", stream_id,
                      window_update_delta);
      break;

    case SPDY_CREDENTIAL:
      /* TODO(hkhalil): Show something meaningful. */
      break;

    default:
      if (spdy_debug) {
        printf("Unhandled SPDY frame type: %d\n", frame_type);
      }
      return -1;
      break;
  }

  /*
   * Process the name-value pairs one at a time, after possibly
   * decompressing the header block.
   */
  if (frame_type == SPDY_SYN_STREAM || frame_type == SPDY_SYN_REPLY) {
    headers_compressed = spdy_check_header_compression(tvb, offset,
                                                       frame_length);
    if (!spdy_decompress_headers || !headers_compressed) {
        header_tvb = tvb;
        hdr_offset = offset;
    } else {
      spdy_frame_info_t *per_frame_info =
          spdy_find_saved_header_block(pinfo->fd,
                                       stream_id,
                                       frame_type == SPDY_SYN_REPLY);
      if (per_frame_info == NULL) {
        guint uncomp_length;
        z_streamp decomp = frame_type == SPDY_SYN_STREAM ?
             conv_data->rqst_decompressor : conv_data->rply_decompressor;
        guint8 *uncomp_ptr =
            spdy_decompress_header_block(tvb, decomp, conv_data->dictionary_id,
                offset, frame_length + 8 - (offset - orig_offset),
                &uncomp_length);
        if (uncomp_ptr == NULL) { /* decompression failed */
          if (spdy_debug) {
              printf("Frame #%d: Inflation failed\n", pinfo->fd->num);
          }
          proto_item_append_text(spdy_proto,
                                 " [Error: Header decompression failed]");
          /* Should we just bail here? */
        } else {
          if (spdy_debug) {
            printf("Saving %u bytes of uncomp hdr\n", uncomp_length);
          }
          per_frame_info =
            spdy_save_header_block(pinfo->fd, stream_id,
                                   frame_type == SPDY_SYN_REPLY, uncomp_ptr,
                                   uncomp_length);
        }
      } else if (spdy_debug) {
        printf("Found uncompressed header block len %u for stream %u "
               "frame_type=%d\n",
               per_frame_info->header_block_len,
               per_frame_info->stream_id,
               per_frame_info->frame_type);
      }
      if (per_frame_info != NULL) {
        header_tvb = tvb_new_child_real_data(tvb,
                                         per_frame_info->header_block,
                                         per_frame_info->header_block_len,
                                         per_frame_info->header_block_len);
        add_new_data_source(pinfo, header_tvb, "Uncompressed headers");
        hdr_offset = 0;
      }
    }
    num_headers = tvb_get_ntohl(header_tvb, hdr_offset);
    if (header_tvb == NULL ||
        (headers_compressed && !spdy_decompress_headers)) {
      num_headers = 0;
      ti = proto_tree_add_string(sub_tree, hf_spdy_num_headers_string, tvb,
                                 frame_type == SPDY_SYN_STREAM ?
                                    orig_offset + 18 : orig_offset + 12,
                                 2,
                                 "Unknown (header block is compressed)");
    } else {
      ti = proto_tree_add_item(sub_tree,
                               hf_spdy_num_headers,
                               header_tvb,
                               hdr_offset,
                               4,
                               ENC_BIG_ENDIAN);
    }
    hdr_offset += 4;
  }

  /* TODO(hkhalil): Remove this escape hatch, process headers as possible. */
  if (num_headers > frame_length) {
    printf("Number of headers is greater than frame length!\n");
    proto_item_append_text(ti, " [Error: Number of headers is larger than "
                           "frame length]");
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%u]", frame_type_name,
                    stream_id);
    return frame_length+8;
  }

  /* Process headers. */
  hdr_verb = hdr_url = hdr_version = content_type = content_encoding = NULL;
  while (num_headers-- &&
         tvb_reported_length_remaining(header_tvb, hdr_offset) != 0) {
    gchar *header_name;
    gchar *header_value;
    proto_tree *header_tree;
    proto_item *header;
    proto_item *header_name_ti;
    proto_item *header_value_ti;
    int header_name_offset;
    int header_value_offset;
    guint32 header_name_length;
    guint32 header_value_length;

    /* Get header name details. */
    header_name_offset = hdr_offset;
    header_name_length = tvb_get_ntohl(header_tvb, hdr_offset);
    hdr_offset += 4;
    header_name = (gchar *)tvb_get_ephemeral_string(header_tvb,
                                                    hdr_offset,
                                                    header_name_length);
    hdr_offset += header_name_length;

    /* Get header value details. */
    header_value_offset = hdr_offset;
    header_value_length = tvb_get_ntohl(header_tvb, hdr_offset);
    hdr_offset += 4;
    header_value = (gchar *)tvb_get_ephemeral_string(header_tvb,
                                                     hdr_offset,
                                                     header_value_length);
    hdr_offset += header_value_length;

    /* Populate tree with header name/value details. */
    if (tree) {
      /* Add 'Header' subtree with description. */
      header = proto_tree_add_item(spdy_tree,
                                   hf_spdy_header,
                                   header_tvb,
                                   header_name_offset,
                                   hdr_offset - header_name_offset,
                                   ENC_NA);
      proto_item_append_text(header, ": %s: %s", header_name, header_value);
      header_tree = proto_item_add_subtree(header, ett_spdy_header);

      /* Add header name. */
      header_name_ti = proto_tree_add_item(header_tree,
                                           hf_spdy_header_name,
                                           header_tvb,
                                           header_name_offset,
                                           4,
                                           ENC_NA);

      /* Add 'Value' subtree with descriptive text. */
      header_value_ti = proto_tree_add_item(header_tree,
                                            hf_spdy_header_value,
                                            header_tvb,
                                            header_value_offset,
                                            4,
                                            ENC_NA);
    }
    if (spdy_debug) {
      printf("    %s: %s\n", header_name, header_value);
    }
    /*
     * TODO(ers) check that the header name contains only legal characters.
     */
    if (g_ascii_strcasecmp(header_name, "method") == 0 ||
      g_ascii_strcasecmp(header_name, "status") == 0) {
      hdr_verb = header_value;
    } else if (g_ascii_strcasecmp(header_name, "url") == 0) {
      hdr_url = header_value;
    } else if (g_ascii_strcasecmp(header_name, "version") == 0) {
      hdr_version = header_value;
    } else if (g_ascii_strcasecmp(header_name, "content-type") == 0) {
      content_type = se_strdup(header_value);
    } else if (g_ascii_strcasecmp(header_name, "content-encoding") == 0) {
      content_encoding = se_strdup(header_value);
    }
  }

  /* Set Info column. */
  if (hdr_version != NULL) {
    if (hdr_url != NULL) {
      col_append_fstr(pinfo->cinfo, COL_INFO, ": %s %s %s",
                      hdr_verb, hdr_url, hdr_version);
    } else {
      col_append_fstr(pinfo->cinfo, COL_INFO, ": %s %s",
                   hdr_verb, hdr_version);
    }
  }
  /*
   * If we expect data on this stream, we need to remember the content
   * type and content encoding.
   */
  if (content_type != NULL && !pinfo->fd->flags.visited) {
    gchar *content_type_params = spdy_parse_content_type(content_type);
    spdy_save_stream_info(conv_data, stream_id, content_type,
                          content_type_params, content_encoding);
  }

  /* Assume that we've consumed the whole frame. */
  return 8 + frame_length;
}

static guint get_spdy_message_len(packet_info *UNUSED(pinfo), tvbuff_t *tvb,
                                  int offset) {
  return (guint)tvb_get_ntoh24(tvb, offset + 5) + 8;
}

/*
 * Wrapper for dissect_spdy_frame, sets fencing and desegments as necessary.
 */
static int dissect_spdy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  spdy_conv_t *conv_data = NULL;
  int offset = 0;
  int expected_frame_len = 0;
  int dissected_len = 0;
  int remaining_len = tvb_reported_length_remaining(tvb, offset);

  /* Loop over the buffer. */
  while (remaining_len > 0) {
    /* Make sure that we have at least the next frame header. */
    if (remaining_len < 8) {
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return offset;
    }

    /* Make sure that we have enough data for the next whole frame. */
    expected_frame_len = get_spdy_message_len(pinfo, tvb, offset);
    if (expected_frame_len > remaining_len) {
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = expected_frame_len - remaining_len;
      return offset;
    }

    /* Dissect the frame. */
    conv_data = get_or_create_spdy_conversation_data(pinfo);
    dissected_len = dissect_spdy_frame(tvb, offset, pinfo, tree, conv_data);
    if (dissected_len != expected_frame_len) {
      if (spdy_debug) {
        printf("Error decoding SPDY frame!");
      }
      return offset;
    }
    offset += dissected_len;
    remaining_len = tvb_reported_length_remaining(tvb, offset);

    /*
     * OK, we've set the Protocol and Info columns for the
     * first SPDY message; set a fence so that subsequent
     * SPDY messages don't overwrite the Info column.
     */
    col_set_fence(pinfo->cinfo, COL_INFO);
  }

  /* Return the number of bytes processed. */
  return offset;
}

/*
 * Looks for SPDY frame at tvb start.
 * If not enough data for either, requests more via desegment struct.
 */
static gboolean dissect_spdy_heur(tvbuff_t *tvb,
                                  packet_info *pinfo,
                                  proto_tree *tree) {
  int old_desegment_offset = pinfo->desegment_offset;
  int old_desegment_len = pinfo->desegment_len;

  /*
   * The first byte of a SPDY frame must be either 0 or
   * 0x80. If it's not, assume that this is not SPDY.
   * (In theory, a data frame could have a stream ID
   * >= 2^24, in which case it won't have 0 for a first
   * byte, but this is a pretty reliable heuristic for
   * now.)
   */
  guint8 first_byte = tvb_get_guint8(tvb, 0);
  if (first_byte != 0x80 && first_byte != 0x0) {
    return FALSE;
  }

  /* Attempt dissection. */
  if (dissect_spdy(tvb, pinfo, tree) != 0) {
    return TRUE;
  }

  /* Revert any work that we did. */
  pinfo->desegment_offset = old_desegment_offset;
  pinfo->desegment_len = old_desegment_len;

  return FALSE;
}

/*
 * Called when the plugin will be working on a completely new capture.
 */
static void reinit_spdy(void) {
}

/* NMAKE complains about flags_set_truth not being constant. Duplicate
 * the values inside of it. */
static const true_false_string tfs_spdy_set_notset = { "Set", "Not set" };

/*
 * Performs plugin registration.
 */
void proto_register_spdy(void) {
  static hf_register_info hf[] = {
    { &hf_spdy_syn_stream,
      { "Syn Stream",     "spdy.syn_stream",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_syn_reply,
      { "Syn Reply",      "spdy.syn_reply",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_headers,
      { "Headers",        "spdy.headers",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_data,
      { "Data",           "spdy.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_control_bit,
      { "Control bit",    "spdy.control_bit",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "TRUE if SPDY control frame", HFILL
      }
    },
    { &hf_spdy_version,
      { "Version",        "spdy.version",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_type,
      { "Type",           "spdy.type",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_flags,
      { "Flags",          "spdy.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_flags_fin,
      { "Fin",            "spdy.flags.fin",
        FT_BOOLEAN, 8, TFS(&tfs_spdy_set_notset),
        SPDY_FIN, "", HFILL
      }
    },
    { &hf_spdy_length,
      { "Length",         "spdy.length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_header,
      { "Header",         "spdy.header",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "", HFILL
      }
    },
    { &hf_spdy_header_name,
      { "Name",           "spdy.header.name",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "", HFILL
      }
    },
    { &hf_spdy_header_value,
      { "Value",          "spdy.header.value",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "", HFILL
      }
    },
    { &hf_spdy_streamid,
      { "Stream ID",      "spdy.streamid",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "", HFILL
      }
    },
    { &hf_spdy_associated_streamid,
      { "Associated Stream ID",   "spdy.associated.streamid",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "", HFILL
      }
    },
    { &hf_spdy_priority,
      { "Priority",       "spdy.priority",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "", HFILL
      }
    },
    { &hf_spdy_num_headers,
      { "Number of headers", "spdy.numheaders",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "", HFILL
      }
    },
    { &hf_spdy_num_headers_string,
      { "Number of headers", "spdy.numheaders",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "", HFILL
      }
    },
  };
  static gint *ett[] = {
    &ett_spdy,
    &ett_spdy_syn_stream,
    &ett_spdy_syn_reply,
    &ett_spdy_fin_stream,
    &ett_spdy_flags,
    &ett_spdy_header,
    &ett_spdy_header_name,
    &ett_spdy_header_value,
    &ett_spdy_encoded_entity,
  };

  module_t *spdy_module;

  proto_spdy = proto_register_protocol("SPDY", "SPDY", "spdy");
  proto_register_field_array(proto_spdy, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  new_register_dissector("spdy", dissect_spdy, proto_spdy);
  spdy_module = prefs_register_protocol(proto_spdy, reinit_spdy);
  prefs_register_bool_preference(spdy_module, "assemble_data_frames",
                                 "Assemble SPDY bodies that consist of multiple DATA frames",
                                 "Whether the SPDY dissector should reassemble multiple "
                                 "data frames into an entity body.",
                                 &spdy_assemble_entity_bodies);
#ifdef HAVE_LIBZ
  prefs_register_bool_preference(spdy_module, "decompress_headers",
                                 "Uncompress SPDY headers",
                                 "Whether to uncompress SPDY headers.",
                                 &spdy_decompress_headers);
  prefs_register_bool_preference(spdy_module, "decompress_body",
                                 "Uncompress entity bodies",
                                 "Whether to uncompress entity bodies that are compressed "
                                 "using \"Content-Encoding: \"",
                                 &spdy_decompress_body);
#endif
  prefs_register_bool_preference(spdy_module, "debug_output",
                                 "Print debug info on stdout",
                                 "Print debug info on stdout",
                                 &spdy_debug);

  /** Create dissector handle and register for dissection. */
  spdy_handle = new_create_dissector_handle(dissect_spdy, proto_spdy);
  dissector_add_uint("tcp.port", TCP_PORT_SPDY, spdy_handle);
  ssl_dissector_add(SSL_PORT_SPDY, "spdy", TRUE);

  /*
   * Register for tapping
   */
  spdy_tap = register_tap("spdy"); /* SPDY statistics tap */
  spdy_eo_tap = register_tap("spdy_eo"); /* SPDY Export Object tap */
}

void proto_reg_handoff_spdy(void) {
  data_handle = find_dissector("data");
  media_handle = find_dissector("media");
  heur_dissector_add("tcp", dissect_spdy_heur, proto_spdy);
}
