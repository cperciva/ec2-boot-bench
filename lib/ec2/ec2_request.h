#ifndef _EC2_REQUEST_H_
#define _EC2_REQUEST_H_

#include <stddef.h>
#include <stdint.h>

/* Opaque types. */
struct http_response;
struct sock_addr;

/**
 * ec2_request(addrs, key_id, key_secret, region, body, bodylen, maxrlen,
 *     callback, cookie):
 * Using the AWS Key ID ${key_id} and Secret Access Key ${key_secret}, send
 * the EC2 request contained in ${body} (of length ${bodylen}) to region
 * ${region} located at ${addrs}.
 *
 * Read a response with a body of up to ${maxrlen} bytes and invoke the
 * provided callback as ${callback}(${cookie}, ${response}), with a response
 * of NULL if no response was read (e.g., on connection error).  Return a
 * cookie which can be passed to http_request_cancel() to abort the request.
 *
 * If the HTTP response has no body, the response structure will have bodylen
 * == 0 and body == NULL; if there is a body larger than ${maxrlen} bytes,
 * the response structure will have bodylen == (size_t)(-1) and body == NULL.
 * The callback is responsible for freeing the response body buffer (if any),
 * but not the rest of the response; it must copy any header strings before it
 * returns.  The provided request body buffer must remain valid until the
 * callback is invoked.
 */
void * ec2_request(struct sock_addr * const *, const char *, const char *,
    const char *, const uint8_t *, size_t, size_t,
    int (*)(void *, struct http_response *), void *);

#endif /* !_EC2_REQUEST_H_ */
