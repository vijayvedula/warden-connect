/* wc_kong.h — the C ABI a Kong Lua plugin drives over LuaJIT FFI.
 *
 * Kept by hand rather than generated: it is the contract, and a generated header would let a
 * change to a Rust signature silently become a change to what Lua is told. crates/wc-kong's
 * test suite compiles this file and calls through it, so a divergence is a build failure.
 *
 * Ownership
 *   Rust allocates every wc_out buffer. Call wc_out_free on any wc_out a call filled, whatever
 *   it returned. Never free ptr with free().
 *
 * Failure
 *   Negative returns are failures and every one of them means refuse the call. A panic inside
 *   the library is caught at this boundary and surfaces as WC_ERR_PANIC; the worker survives.
 */
#ifndef WC_KONG_H
#define WC_KONG_H

#include <stddef.h>
#include <stdint.h>

/* verdicts */
#define WC_FORWARD     0   /* forward the frame unchanged                       */
#define WC_REFUSE      1   /* return out.ptr[0..len] to the client, status 200   */
#define WC_BUFFER      2   /* buffer the response body for wc_on_response_body   */
#define WC_SKIP        3   /* stream the response body through untouched         */
#define WC_PASS        4   /* send the buffered body on unchanged                */
#define WC_REWRITE     5   /* replace the body with out.ptr[0..len]              */

/* failures — all of them mean refuse */
#define WC_ERR_PANIC  (-1)
#define WC_ERR_BADARG (-2)
#define WC_ERR_CONFIG (-3)

typedef struct wc_handle wc_handle;
typedef struct wc_stream wc_stream;

typedef struct {
  uint8_t *ptr;   /* bytes owned by Rust, or NULL       */
  size_t   len;
  int      code;  /* WC-4002 arrives as 4002; 0 = none  */
} wc_out;

/* lifecycle — once per nginx worker */
wc_handle *wc_init(const uint8_t *cfg_json, size_t len, wc_out *err);
void       wc_free(wc_handle *h);
int        wc_contract_count(const wc_handle *h);
const char *wc_version(void);

/* per request */
wc_stream *wc_stream_new(const wc_handle *h, const uint8_t *peer_json, size_t len, wc_out *err);
void       wc_stream_free(wc_stream *s);

int wc_on_request(wc_stream *s, const uint8_t *body, size_t len, wc_out *out);
int wc_on_response_headers(wc_stream *s, const uint8_t *ctype, size_t len, wc_out *out);
int wc_on_response_body(wc_stream *s, const uint8_t *body, size_t len, wc_out *out);

void wc_out_free(wc_out *out);

#endif /* WC_KONG_H */
