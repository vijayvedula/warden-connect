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
 *
 * ---------------------------------------------------------------------------
 * wc_init config JSON
 * ---------------------------------------------------------------------------
 *   contracts    [string]   paths to *.jws artifacts. Empty is a startup error.
 *   routes       string     path to routes.toml. Kong's SERVICE name matches the
 *                           `cluster` column; its ROUTE name matches `route`.
 *   identity     string     "tls" | "xfcc". REQUIRED, no default.
 *   mesh_origin  string     required with "xfcc", forbidden with "tls". A leading
 *                           '/' means a unix socket; otherwise an address.
 *   issuer_pub   string     path to a PEM  (with kid)   ) exactly
 *   jwks_file    string     path to a JWKS             ) one
 *   jwks_url     string     URL of a JWKS              ) of these
 *   kid          string     key id, required with issuer_pub
 *   mediator_id  string     who the contracts must be addressed to
 *   issuer_id    string     which control plane they must come from
 *   mode         string     "enforce" (default) | "observe"
 *   pin_max_age  number     seconds a pin verification stays good. 0 = forever.
 *   max_stale    number     seconds the set may go unrefreshed. 0 = no bound.
 *   any_zone     bool       allow any zone pair. Default false.
 *   no_pin       bool       disable the surface pin. Default false. Gate 8 is not
 *                           optional; this exists for a staged rollout only.
 *
 * ---------------------------------------------------------------------------
 * wc_stream_new peer JSON
 * ---------------------------------------------------------------------------
 * There is no `caller` field, and there must never be one: a field in which Lua
 * states an identity is a field in which anything reaching Lua states an identity.
 * Identity is derived from evidence, by whichever source `identity` names.
 *
 *   identity = "tls"                     from Lua
 *     tls_verify  string   ngx.var.ssl_client_verify. Only "SUCCESS" is an identity.
 *     cert_pem    string   ngx.var.ssl_client_raw_cert. Leaf first.
 *     remote      string   ngx.var.remote_addr
 *
 *   identity = "xfcc"
 *     xfcc        string   the x-forwarded-client-cert header
 *     remote      string   ngx.var.remote_addr, or "unix:<listener path>"
 *
 *   both
 *     service     string   kong.router.get_service().name
 *     route       string   kong.router.get_route().name
 *
 * `remote` is EVIDENCE and must come from the request. Deriving it from the
 * configured mesh_origin makes the origin always equal the trusted one, which
 * turns the mesh check into a no-op and lets any client that can set the header
 * assert any identity.
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
