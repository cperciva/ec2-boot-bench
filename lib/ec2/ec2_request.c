#include <stdlib.h>
#include <string.h>

#include "asprintf.h"
#include "aws_sign.h"
#include "http.h"
#include "warnp.h"

#include "ec2_request.h"

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
void *
ec2_request(struct sock_addr * const * addrs, const char * key_id,
    const char * key_secret, const char * region, const uint8_t * body,
    size_t bodylen, size_t maxrlen,
    int (* callback)(void *, struct http_response *), void * cookie)
{
	struct http_request RH;
	struct http_header RHH[5];
	char * x_amz_content_sha256;
	char * x_amz_date;
	char * authorization;
	char * host;
	char * content_length;
	void * http_cookie;

	/* Sign request. */
	if (aws_sign_ec2_headers(key_id, key_secret, region, body, bodylen,
	    &x_amz_content_sha256, &x_amz_date, &authorization)) {
		warnp("Failed to sign EC2 POST request");
		goto err0;
	}

	/* Construct Host header. */
	if (asprintf(&host, "ec2.%s.amazonaws.com", region) == -1)
		goto err1;

	/* Construct Content-Length header. */
	if (asprintf(&content_length, "%zu", bodylen) ==  -1)
		goto err2;

	/* Construct HTTP request structure. */
	RH.method = "POST";
	RH.path = "/";
	RH.bodylen = bodylen;
	RH.body = body;
	RH.nheaders = 5;
	RH.headers = RHH;

	/* Fill in headers. */
	RHH[0].header = "Host";
	RHH[0].value = host;
	RHH[1].header = "X-Amz-Date";
	RHH[1].value = x_amz_date;
	RHH[2].header = "X-Amz-Content-SHA256";
	RHH[2].value = x_amz_content_sha256;
	RHH[3].header = "Authorization";
	RHH[3].value = authorization;
	RHH[4].header = "Content-Length";
	RHH[4].value = content_length;

	/* Send the request. */
	if ((http_cookie = https_request(addrs, &RH, maxrlen,
	    callback, cookie, host)) == NULL)
		goto err3;

	/* Free strings allocated by asprintf. */
	free(content_length);
	free(host);

	/* Free headers used for authorization. */
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);

	/* Success! */
	return (http_cookie);

err3:
	free(content_length);
err2:
	free(host);
err1:
	free(authorization);
	free(x_amz_date);
	free(x_amz_content_sha256);
err0:
	/* Failure! */
	return (NULL);
}
