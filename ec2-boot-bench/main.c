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
static const char * subnet_id = NULL;
static const char * user_data_fname = NULL;
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
callback_launch(void * cookie, struct http_response * R)
{

	(void)cookie; /* UNUSED */

	/* Record time after API request to launch instance returns. */
	if (monoclock_get(&t_started)) {
		warnp("monoclock_get");
		goto err0;
	}

	/* Check status. */
	if ((R == NULL) || (R->status != 200)) {
		warn0("EC2 RunInstances API request failed");
		goto err0;
	}

	/* Check that we have a response body. */
	if ((R->bodylen == 0) || (R->bodylen == (size_t)(-1))) {
		warn0("EC2 RunInstances succeeded but no response body?");
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
	    "%s%s%s"
	    "%s%s%s"
	    "MinCount=1&MaxCount=1&"
	    "Ipv6AddressCount=1&"
	    "Version=2016-11-15",
	    ami_id, itype,
	    subnet_id ? "SubnetId=" : "",
	    subnet_id ? subnet_id : "",
	    subnet_id ? "&" : "",
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

	/* Check that we have a response body. */
	if ((R->bodylen == 0) || (R->bodylen == (size_t)(-1))) {
		warn0("EC2 DescribeInstances succeeded but no response body?");
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
callback_terminate(void * cookie, struct http_response * R)
{

	(void)cookie; /* UNUSED */

	/* Check status. */
	if ((R == NULL) || (R->status != 200)) {
		warn0("EC2 TerminateInstances API request failed");
		goto err0;
	}

	/* Check that we have a response body. */
	if ((R->bodylen == 0) || (R->bodylen == (size_t)(-1))) {
		warn0("EC2 TerminateInstances succeeded but no response body?");
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

	fprintf(stderr, "usage: ec2-boot-bench %s %s %s %s [%s] [%s]\n",
	    "--keys <keyfile>", "--region <name>", "--ami <AMI Id>",
	    "--itype <instance type>", "--subnet <subnet Id>",
	    "--user-data <file>");
	exit(1);
}

int
main(int argc, char * argv[])
{
	const char * ch;
	char * ec2api_hostname;

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
		GETOPT_OPTARG("--region"):
			region = optarg;
			break;
		GETOPT_OPTARG("--subnet"):
			subnet_id = optarg;
			break;
		GETOPT_OPTARG("--user-data"):
			user_data_fname = optarg;
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

	return (0);
}
