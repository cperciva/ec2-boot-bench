#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asprintf.h"
#include "aws_readkeys.h"
#include "b64encode.h"
#include "ec2_request.h"
#include "events.h"
#include "getopt.h"
#include "http.h"
#include "mapfile.h"
#include "parsenum.h"
#include "sock.h"
#include "monoclock.h"
#include "warnp.h"

/* TCP ping state. */
struct tcpping {
	int s;
	void * timer_cookie;
};

static const char * ami_id = NULL;
static const char * itype = NULL;
static const char * keyfile = NULL;
static const char * region = NULL;
static const char * security_group = NULL;
static const char * subnet_id = NULL;
static const char * user_data_fname = NULL;
static const char * bootvideo = NULL;
static double fps = 0.0;
static char * key_id;
static char * key_secret;
static struct sock_addr ** ec2api_addrs;
static char * instance_id;
static struct sock_addr ** s_tgt;
static void * timer_cookie;
static struct timeval t_start;
static struct timeval t_started;
static struct timeval t_running;
static struct timeval t_closed;
static struct timeval t_open;
static size_t ndescribes = 0;
static size_t npings = 0;
static int terminated = 0;
static int ipv6 = 1;
static int imgnum = 0;
static char * screenshotdir = NULL;
void * screenshot_timer_cookie;
uint8_t * imgbuf = NULL;
size_t imgbuflen;

static int poke(void);

/*
 * Extract a value from a buffer of XML.  The tag must appear once only and
 * there must not be any nasty stuff (e.g. CDATA).
 */
static char *
xmlextract(const uint8_t * buf, size_t buflen, const char * tagname)
{
	size_t taglen = strlen(tagname);
	const uint8_t * s;
	const uint8_t * e;
	char * val;

	/* Find the opening tag. */
	for (s = buf; (size_t)(s - buf) <= buflen - (taglen + 2); s++) {
		if (s[0] == '<' &&
		    (memcmp(&s[1], tagname, taglen) == 0) &&
		    s[taglen + 1] == '>')
			break;
	}
	if ((size_t)(s - buf) > buflen - (taglen + 2))
		return (NULL);

	/* Advance past the opening tag. */
	s += taglen + 2;

	/* Find the closing tag. */
	for (e = s; (size_t)(e - buf) <= buflen - (taglen + 3); e++) {
		if (e[0] == '<' && e[1] == '/' &&
		    (memcmp(&e[2], tagname, taglen) == 0) &&
		    e[taglen + 2] == '>')
			break;
	}
	if ((size_t)(e - buf) > buflen - (taglen + 3))
		return (NULL);

	/* Duplicate the tag contents. */
	if ((val = malloc(e - s + 1)) == NULL)
		return (NULL);
	memcpy(val, s, e - s);
	val[e - s] = '\0';

	/* Return extracted value. */
	return (val);
}

static int
handle_ec2_errors(const char * api_name, struct http_response * R)
{

	if (R == NULL) {
		warn0("EC2 %s API request failed", api_name);
		return (-1);
	}

	/* Check that we have a response body. */
	if ((R->bodylen == 0) || (R->bodylen == (size_t)(-1))) {
		warn0("EC2 %s API request (status %d) got no response body",
		    api_name, R->status);
		return (-1);
	}

	if (R->status != 200) {
		warn0("EC2 %s API request failed (status %d):\n%.*s",
		    api_name, R->status, R->bodylen, R->body);
		return (-1);
	}

	return (0);
}

static int
callback_launch(void * cookie, struct http_response * R)
{

	(void)cookie; /* UNUSED */

	/* Record time after API request to launch instance returns. */
	if (monoclock_get(&t_started)) {
		warnp("monoclock_get");
		goto err0;
	}

	if (handle_ec2_errors("RunInstances", R)) {
		goto err0;
	}

	/* Extract instance Id. */
	if ((instance_id =
	    xmlextract(R->body, R->bodylen, "instanceId")) == NULL) {
		warn0("Could not find <instanceId> in RunInstances response");
		goto err0;
	}

	/* Free response body. */
	free(R->body);

	/* Do more work. */
	return (poke());

err0:
	/* Failure! */
	return (-1);
}

static int
launch(void)
{
	uint8_t * userdatabuf;
	int fd;
	size_t userdatalen;
	char * userdatahexbuf = NULL;
	char * s;

	/* Load user-data file, if we have one. */
	if (user_data_fname) {
		/* Map the file into memory. */
		if ((userdatabuf =
		    mapfile(user_data_fname, &fd, &userdatalen)) == NULL) {
			warnp("Could not load user-data file: %s",
			    user_data_fname);
			goto err0;
		}

		/* Allocate a buffer for the base64-encoded contents. */
		if ((userdatahexbuf =
		    malloc(b64len(userdatalen) + 1)) == NULL) {
			warnp("malloc");
			unmapfile(userdatabuf, fd, userdatalen);
			goto err0;
		}

		/* Base64-encode the data. */
		b64encode(userdatabuf, userdatahexbuf, userdatalen);

		/* Unmap the user-data file. */
		if (unmapfile(userdatabuf, fd, userdatalen)) {
			warnp("Could not unload user-data file: %s",
			    user_data_fname);
			goto err1;
		}
	}

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=RunInstances&"
	    "ImageId=%s&"
	    "InstanceType=%s&"
	    "NetworkInterface.1.DeviceIndex=0&"
	    "%s%s%s"
	    "%s%s%s"
	    "NetworkInterface.1.%s&"
	    "%s%s%s"
	    "MinCount=1&MaxCount=1&"
	    "Version=2016-11-15",
	    ami_id, itype,
	    subnet_id ? "NetworkInterface.1.SubnetId=" : "",
	    subnet_id ? subnet_id : "",
	    subnet_id ? "&" : "",
	    security_group ? "NetworkInterface.1.SecurityGroupId.1=" : "",
	    security_group ? security_group : "",
	    security_group ? "&" : "",
	    ipv6 ? "Ipv6AddressCount=1" : "AssociatePublicIpAddress=true",
	    user_data_fname ? "UserData=" : "",
	    user_data_fname ? userdatahexbuf : "",
	    user_data_fname ? "&" : "") == -1)
		goto err1;

	/* Record time before making API request to launch instance. */
	if (monoclock_get(&t_start)) {
		warnp("monoclock_get");
		goto err2;
	}

	/* Issue API request. */
	if (ec2_request(ec2api_addrs, key_id, key_secret, region,
	    (const uint8_t *)s, strlen(s), 16384, callback_launch,
	    NULL) == NULL) {
		warnp("ec2_request");
		goto err2;
	}

	/* Success! */
	return (0);

err2:
	free(s);
err1:
	free(userdatahexbuf);
err0:
	/* Failure! */
	return (-1);
}

static int
callback_describe(void * cookie, struct http_response * R)
{
	char * instanceState;
	char * statename;
	char * ip;
	char * tgt;

	(void)cookie; /* UNUSED */

	/*
	 * Silently ignore failed connections and errors from EC2; in
	 * addition to network failures, DescribeInstances may return a 400
	 * InvalidInstanceID.NotFound error due to internal EC2 consistency
	 * issues.
	 */
	if (R == NULL)
		return (0);
	if (R->status != 200)
		goto done;

	if (handle_ec2_errors("DescribeInstances", R)) {
		goto err0;
	}

	/*
	 * If we have already received a response telling us that the instance
	 * is running (and has an IP address) then this DescribeInstances call
	 * was superfluous; return without examining it further.
	 */
	if (t_running.tv_sec != 0)
		goto done;

	/* Extract instance state. */
	if ((instanceState =
	    xmlextract(R->body, R->bodylen, "instanceState")) == NULL) {
		warn0("Could not find <instanceState> in DescribeInstances response");
		goto err1;
	}
	if ((statename = xmlextract((const uint8_t *)instanceState,
	    strlen(instanceState), "name")) == NULL) {
		warnp("Could not find <name> in <instanceState>: %s",
		    instanceState);
		goto err2;
	}

	/*
	 * Try to extract the instance IP address; NULL is fine in this case
	 * since it might not have been assigned an address yet.
	 */
	ip = xmlextract(R->body, R->bodylen, "ipAddress");

	/*
	 * If the state is 'running' and we have an IP address assigned, we
	 * can stop polling now.
	 */
	if ((strcmp(statename, "running") == 0) && (ip != NULL)) {
		/* Record the time. */
		if (monoclock_get(&t_running)) {
			warnp("monoclock_get");
			goto err3;
		}

		/* Stop polling. */
		events_timer_cancel(timer_cookie);
		timer_cookie = NULL;

		/* Construct the target address and parse. */
		if (asprintf(&tgt, "[%s]:22", ip) == -1) {
			warnp("asprintf");
			goto err3;
		}
		if ((s_tgt = sock_resolve(tgt)) == NULL) {
			warnp("sock_resolve");
			goto err4;
		}
		if (s_tgt[0] == NULL) {
			warn0("Could not parse address: %s", tgt);
			goto err4;
		}
		free(tgt);

		/* Kick off the tcp pings. */
		if (poke())
			goto err3;
	}

	/* Free strings we extracted from the API response. */
	free(ip);
	free(statename);
	free(instanceState);

done:
	/* Free response body. */
	free(R->body);

	/* Success! */
	return (0);

err4:
	free(tgt);
err3:
	free(ip);
	free(statename);
err2:
	free(instanceState);
err1:
	free(R->body);
err0:
	/* Failure! */
	return (-1);
}

static int
describe(void)
{
	char * s;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=DescribeInstances&"
	    "InstanceId.1=%s&"
	    "Version=2014-09-01",
	    instance_id) == -1)
		goto err0;

	/* Issue API request. */
	if (ec2_request(ec2api_addrs, key_id, key_secret, region,
	    (const uint8_t *)s, strlen(s), 16384, callback_describe,
	    NULL) == NULL) {
		warnp("ec2_request");
		goto err1;
	}

	/* Success! */
	return (0);

err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

static int
tcpping_timeout(void * cookie)
{
	struct tcpping * P = cookie;

	/* Cancel the network wait and close the socket. */
	events_network_cancel(P->s, EVENTS_NETWORK_OP_WRITE);
	close(P->s);

	/* Free our cookie. */
	free(P);

	/* Success! */
	return (0);
}

static int
tcpping_callback(void * cookie)
{
	struct tcpping * P = cookie;
	int s = P->s;
	int err;
	socklen_t errlen = sizeof(err);

	/* Cancel the timeout and free the cookie. */
	events_timer_cancel(P->timer_cookie);
	free(P);

	/*
	 * If we've already received a SYN/ACK, this tcp ping was superfluous;
	 * return without taking any further action.
	 */
	if (t_open.tv_sec != 0)
		goto done;

	/* Did the connect succeed? */
	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen)) {
		warnp("getsockopt");
		goto err1;
	}

	/* Record timestamps if appropriate. */
	switch (err) {
	case ETIMEDOUT:
		/* The target's TCP stack is not running yet. */
		break;
	case ECONNREFUSED:
		/* The target's TCP stack is running but port is closed. */
		if (t_closed.tv_sec == 0) {
			if (monoclock_get(&t_closed)) {
				warnp("monoclock_get");
				goto err1;
			}
		}
		break;
	case 0:
		/* Connect succeeded; port is open. */
		if (t_open.tv_sec == 0) {
			if (monoclock_get(&t_open)) {
				warnp("monoclock_get");
				goto err1;
			}
		}

		/*
		 * If we never observed the port being closed, record that
		 * now as well; the instance must have moved through that
		 * state fast enough to escape being seen.
		 */
		if (t_closed.tv_sec == 0)
			t_closed = t_open;

		/* Stop TCP pinging and kick off the EC2 terminate call. */
		events_timer_cancel(timer_cookie);
		timer_cookie = NULL;
		if (poke())
			goto err1;
		break;
	default:
		errno = err;
		warnp("non-blocking connect returned error");
		break;
	}

done:
	/* Close the socket; we don't actually want the connection. */
	close(s);

	/* Success! */
	return (0);

err1:
	close(s);

	/* Failure! */
	return (-1);
}

static int
tcpping(void)
{
	struct tcpping * P;

	/* Bake a cookie. */
	if ((P = malloc(sizeof(struct tcpping))) == NULL)
		goto err0;
	P->timer_cookie = NULL;

	/* Attempt to connect to the target. */
	if ((P->s = sock_connect_nb(s_tgt[0])) == -1) {
		/*
		 * It's possible on FreeBSD (and possibly on other systems) to
		 * get EACCES here due to the high rate at which we're sending
		 * SYN packets; it seems to be related to stateful firewalling
		 * combined with source port reuse.  Log those warnings but
		 * don't error out.
		 */
		if (errno == EACCES) {
			warn0("Received EACCES when attempting to connect");
			free(P);
			goto done;
		}
		warnp("sock_connect_nb");
		goto err1;
	}

	/* Wait until it is writable (aka connection completed or failed). */
	if (events_network_register(tcpping_callback, P, P->s,
	    EVENTS_NETWORK_OP_WRITE)) {
		warnp("events_network_register");
		goto err2;
	}

	/* Time out after 1 second. */
	if ((P->timer_cookie =
	    events_timer_register_double(tcpping_timeout, P, 1.0)) == NULL) {
		warnp("events_timer_register_double");
		goto err3;
	}

done:
	/* Success! */
	return (0);

err3:
	events_network_cancel(P->s, EVENTS_NETWORK_OP_WRITE);
err2:
	close(P->s);
err1:
	free(P);
err0:
	/* Failure! */
	return (-1);
}

static int
callback_screenshot(void * cookie, struct http_response * R)
{
	char * imagedata = NULL;
	char * s;
	FILE * f;

	(void)cookie; /* UNUSED */

	/*
	 * HTTP 429 errors can occur if we send screenshot requests too fast.
	 * HTTP 500 errors can also occur for the same reason, oddly enough.
	 * Other errors may also occur; in all cases, reuse the previous
	 * screenshot if we have one, in order to keep the constant frame rate.
	 */
	if (R == NULL)
		warn0("GetConsoleScreenshot failed%s",
		    imgbuf ? "; reusing previous frame" : "");
	else if (R->status != 200)
		warn0("GetConsoleScreenshot failed with status %d%s",
		    R->status,
		    imgbuf ? "; reusing previous frame" : "");
	else {
		/* Extract image from response. */
		if ((imagedata =
		    xmlextract(R->body, R->bodylen, "imageData")) == NULL) {
			warn0("Could not find <imagedata>"
			    " in GetConsoleScreenshot response");
			goto err1;
		}

		/* Free the previous frame, if we had one. */
		free(imgbuf);

		/* Decode the base64-encoded image. */
		imgbuflen = strlen(imagedata);
		if ((imgbuf = malloc(imgbuflen)) == NULL)
			goto err2;
		if (b64decode(imagedata, imgbuflen, imgbuf, &imgbuflen)) {
			warn0("Invalid base64-encoded image received");
			goto err2;
		}
	}

	/* If we don't have an image yet, exit early. */
	if (imgbuf == NULL)
		goto done;

	/* Write image to file. */
	if (asprintf(&s, "%s/img%05d.jpg", screenshotdir, imgnum++) == -1)
		goto err2;
	if ((f = fopen(s, "w")) == NULL) {
		warnp("fopen");
		goto err3;
	}
	if (fwrite(imgbuf, imgbuflen, 1, f) != 1) {
		warnp("fwrite");
		goto err4;
	}
	fclose(f);
	free(s);

	/* Free extracted image data (or free(NULL) if frame missing). */
	free(imagedata);

	/* Free response body, if we had one. */
done:
	if (R != NULL)
		free(R->body);

	/* Success! */
	return (0);

err4:
	fclose(f);
err3:
	free(s);
err2:
	free(imagedata);
err1:
	if (R != NULL)
		free(R->body);
err0:
	/* Failure! */
	return (-1);
}

static int
screenshot(void)
{
	char * s;

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=GetConsoleScreenshot&"
	    "InstanceId=%s&"
	    "Version=2016-11-15",
	    instance_id) == -1)
		goto err0;

	/* Issue API request. */
	if (ec2_request(ec2api_addrs, key_id, key_secret,
	    region, (const uint8_t *)s, strlen(s), 1048576, callback_screenshot,
	    NULL) == NULL) {
		warnp("ec2_request");
		goto err1;
	}

	/* Success! */
	return (0);

err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

static int
screenshot_tick(void * cookie)
{

	(void)cookie; /* UNUSED */

	/* Schedule the next screenshot. */
	screenshot_timer_cookie = events_timer_register_double(screenshot_tick,
	    NULL, 1.0 / fps);
	if (screenshot_timer_cookie == NULL) {
		warnp("events_timer_register_double");
		goto err0;
	}

	/* Take a screenshot now. */
	if (screenshot())
		goto err0;

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

static int
domovie(void)
{
	char * tmpmovie;
	char * cmdline;
	FILE * f_in;
	FILE * f_out;
	uint8_t buf[4096];
	size_t lenread;
	size_t i;
	char * s;

	/* Generate a movie from the frames we captured. */
	if (asprintf(&tmpmovie, "%s/out.mp4", screenshotdir) == -1) {
		warnp("asprintf");
		goto err0;
	}
	if (asprintf(&cmdline, "ffmpeg -framerate %f -loglevel warning"
	    " -i %s/img%%05d.jpg %s", fps, screenshotdir, tmpmovie) == -1) {
		warnp("asprintf");
		goto err1;
	}
	if (system(cmdline)) {
		warnp("ffmpeg execution failed");
		goto err2;
	}

	/*
	 * Copy the generated movie to the target file name.  We do this rather
	 * than asking ffmpeg to generate the file directly into the requested
	 * location because we're invoking ffmpeg with system(3) and don't want
	 * to worry about escaping hazardous characters in the file name.
	 */
	if ((f_in = fopen(tmpmovie, "r")) == NULL) {
		warnp("fopen(%s)", tmpmovie);
		goto err2;
	}
	if ((f_out = fopen(bootvideo, "w")) == NULL) {
		warnp("fopen(%s)", bootvideo);
		goto err3;
	}
	do {
		lenread = fread(buf, 1, 4096, f_in);
		if (lenread == 0)
			break;
		if (fwrite(buf, lenread, 1, f_out) != 1) {
			warnp("fwrite");
			goto err4;
		}
	} while (1);
	if (ferror(f_in)) {
		warnp("fread(%s)", tmpmovie);
		goto err4;
	}

	/* Clean up temporary files. */
	unlink(tmpmovie);
	for (i = 0; i < imgnum; i++) {
		if (asprintf(&s, "%s/img%05d.jpg", screenshotdir, i) == -1) {
			warnp("asprintf");
			goto err4;
		}
		unlink(s);
		free(s);
	}
	rmdir(screenshotdir);

	/* Close files used for copying movie. */
	fclose(f_out);
	fclose(f_in);

	/* Free temporary strings. */
	free(cmdline);
	free(tmpmovie);

	/* Success! */
	return (0);

err4:
	fclose(f_out);
err3:
	fclose(f_in);
err2:
	free(cmdline);
err1:
	free(tmpmovie);
err0:
	/* Failure! */
	return (-1);
}

static int
callback_terminate(void * cookie, struct http_response * R)
{

	(void)cookie; /* UNUSED */

	if (handle_ec2_errors("TerminateInstances", R)) {
		goto err0;
	}

	/* The instance was successfully terminated. */
	terminated = 1;

	/* Free response body. */
	free(R->body);

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

static int
terminate(void)
{
	char * s;

	/* Shut down screenshotting if in process. */
	if (screenshot_timer_cookie)
		events_timer_cancel(screenshot_timer_cookie);

	/* Generate EC2 API request. */
	if (asprintf(&s,
	    "Action=TerminateInstances&"
	    "InstanceId.1=%s&"
	    "Version=2014-09-01",
	    instance_id) == -1)
		goto err0;

	/* Issue API request. */
	if (ec2_request(ec2api_addrs, key_id, key_secret, region,
	    (const uint8_t *)s, strlen(s), 16384, callback_terminate,
	    NULL) == NULL) {
		warnp("ec2_request");
		goto err1;
	}

	/* Success! */
	return (0);

err1:
	free(s);
err0:
	/* Failure! */
	return (-1);
}

static int
tick(void * cookie)
{

	(void)cookie; /* UNUSED */

	/* Callback is no longer pending. */
	timer_cookie = NULL;

	/* Do whatever needs to be done. */
	return (poke());
}

static int
poke(void)
{
	struct timeval t_now;

	/* If the instance isn't launched yet, launch it. */
	if (t_start.tv_sec == 0)
		return (launch());

	/* We should have a 'started' time when we get back here. */
	assert(t_started.tv_sec != 0);

	/* If we haven't observed 'running', describe the instance. */
	if (t_running.tv_sec == 0) {
		/* Don't try too many times. */
		if (++ndescribes == 20 * 120)
			goto diediedie;

		/* Describe the instance. */
		if (describe())
			goto err0;

		/* ... and come back in 50 ms to look again. */
		assert(timer_cookie == NULL);
		if ((timer_cookie =
		    events_timer_register_double(tick, NULL, 0.05)) == NULL) {
			warnp("events_timer_register_double");
			goto err0;
		}

		/* All done. */
		return (0);
	}

	/*
	 * If we want to generate a movie and we're not already taking
	 * console screenshots, start taking them.
	 */
	if ((fps > 0.0) && (screenshot_timer_cookie == NULL)) {
		if (screenshot_tick(NULL))
			goto err0;
	}

	/* We should have a target for SYN pings. */
	assert((s_tgt != NULL) && (s_tgt[0] != NULL));

	/* If the port is not yet open, send a SYN ping. */
	if (t_open.tv_sec == 0) {
		/* Don't try too many times. */
		if (++npings == 100 * 600)
			goto diediedie;

		/* Send a SYN ping. */
		if (tcpping())
			goto err0;

		/* ... and come back in 10 ms to send another. */
		assert(timer_cookie == NULL);
		if ((timer_cookie =
		    events_timer_register_double(tick, NULL, 0.01)) == NULL) {
			warnp("events_timer_register_double");
			goto err0;
		}

		/* All done. */
		return (0);
	}

	/*
	 * If we're generating a movie, wait at least 2 seconds and at least
	 * 5 frames extra, in order to capture anything which happens after
	 * the SSH port opens and also to allow the movie to "hold" on the
	 * final frame in case it's played in a loop.
	 */
	monoclock_get(&t_now);
	if ((fps > 0) && ((timeval_diff(t_open, t_now) < 2.0) ||
	    (timeval_diff(t_open, t_now) < 5.0 / fps))) {
		/* Come back later. */
		assert(timer_cookie == NULL);
		if ((timer_cookie =
		    events_timer_register_double(tick, NULL, 0.1)) == NULL) {
			warnp("events_timer_register_double");
			goto err0;
		}

		/* All done. */
		return (0);
	}

diediedie:
	/* Terminate the instance. */
	if (terminate())
		goto err0;

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

static void
usage(void)
{

	fprintf(stderr, "usage: ec2-boot-bench %s %s %s %s"
	    " [%s] [%s] [%s] [%s] [%s [%s]]\n",
	    "--keys <keyfile>", "--region <name>", "--ami <AMI Id>",
	    "--itype <instance type>", "--no-ipv6",
	    "--security-group <security group Id>", "--subnet <subnet Id>",
	    "--user-data <file>", "--bootvideo <file>",
	    "--fps <frame rate>");
	exit(1);
}

int
main(int argc, char * argv[])
{
	const char * ch;
	char * ec2api_hostname;
	const char * tmpdir;

	WARNP_INIT;

	/* Parse command line. */
	while ((ch = GETOPT(argc, argv)) != NULL) {
		GETOPT_SWITCH(ch) {
		GETOPT_OPTARG("--ami"):
			ami_id = optarg;
			break;
		GETOPT_OPTARG("--itype"):
			itype = optarg;
			break;
		GETOPT_OPTARG("--keys"):
			keyfile = optarg;
			break;
		GETOPT_OPT("--no-ipv6"):
			ipv6 = 0;
			break;
		GETOPT_OPTARG("--region"):
			region = optarg;
			break;
		GETOPT_OPTARG("--security-group"):
			security_group = optarg;
			break;
		GETOPT_OPTARG("--subnet"):
			subnet_id = optarg;
			break;
		GETOPT_OPTARG("--user-data"):
			user_data_fname = optarg;
			break;
		GETOPT_OPTARG("--bootvideo"):
			bootvideo = optarg;
			break;
		GETOPT_OPTARG("--fps"):
			if (PARSENUM(&fps, optarg, 0, INFINITY)) {
				warnp("Cannot parse: %s %s", ch, optarg);
				exit(1);
			}
			break;
		GETOPT_MISSING_ARG:
			fprintf(stderr, "missing argument\n");
			/* FALLTHROUGH */
		GETOPT_DEFAULT:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* Check arguments. */
	if (argc != 0)
		usage();
	if ((ami_id == NULL) || (keyfile == NULL) || (itype == NULL) ||
	    (region == NULL))
		usage();
	if ((bootvideo == NULL) && (fps != 0.0))
		usage();

	/* Check frame rate. */
	if (bootvideo != NULL) {
		/* Set default if frame rate not set. */
		if (fps == 0.0)
			fps = 1.0;

		/* Warn about high frame rates. */
		if (fps > 1.0)
			warn0("Requested fps rate exceeds default"
			    " EC2 throttling limit of 1 request per second"
			    " for GetConsoleScreenshot");
	}

	/* Load AWS keys. */
	if (aws_readkeys(keyfile, &key_id, &key_secret)) {
		warnp("Cannot read AWS keys");
		exit(1);
	}

	/* Look up addresses for EC2 API endpoint. */
	if (asprintf(&ec2api_hostname,
	    "ec2.%s.amazonaws.com:443", region) == -1) {
		warnp("asprintf");
		exit(1);
	}
	if ((ec2api_addrs = sock_resolve(ec2api_hostname)) == NULL) {
		warnp("sock_resolve(%s)", ec2api_hostname);
		exit(1);
	}

	/* If we're making a movie, create a temporary directory. */
	if (bootvideo != NULL) {
		if ((tmpdir = getenv("TMPDIR")) == NULL)
			tmpdir = "/tmp";
		if (asprintf(&screenshotdir, "%s/bootvideo.XXXXXXXX",
		    tmpdir) == -1) {
			warnp("asprintf");
			exit(1);
		}
		if (mkdtemp(screenshotdir) == NULL) {
			warnp("mkdtemp");
			exit(1);
		}
	}

	/* Kick things off... */
	if (poke())
		exit(1);

	/* ... and wait until the instance has been terminated. */
	if (events_spin(&terminated)) {
		warnp("Error in event loop");
		exit(1);
	}

	/* Set fictitious times to make output parsing easier. */
	if (t_closed.tv_sec == 0) {
		t_closed = t_running;
		t_closed.tv_sec += 120;
	}
	if (t_open.tv_sec == 0) {
		t_open = t_closed;
		t_open.tv_sec += 120;
	}

	/* Report on how long each step took. */
	printf("RunInstances API call took: %0.6f s\n",
	    timeval_diff(t_start, t_started));
	printf("Moving from pending to running took: %0.6f s\n",
	    timeval_diff(t_started, t_running));
	printf("Moving from running to port closed took: %0.6f s\n",
	    timeval_diff(t_running, t_closed));
	printf("Moving from port closed to port open took: %0.6f s\n",
	    timeval_diff(t_closed, t_open));

	/* Generate movie if requested. */
	if (fps > 0.0) {
		printf("Generating boot movie using ffmpeg"
		    "from %d frames...\n", imgnum);
		if (domovie())
			exit(1);
	}

	return (0);
}
