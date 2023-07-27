/*
 * libslackrtm -- Client library for Slack RTM
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This library is free software, distributed under the terms of
 * the GNU Lesser General Public License Version 2.1. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Client library for Slack RTM (Real Time Messaging) - high-level APIs
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define _GNU_SOURCE /* memmem in string.h */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <arpa/inet.h> /* use inet_ntop */
#include <netdb.h> /* use getnameinfo */

#include <search.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <jansson.h>

#include <wss.h> /* libwss */

#define SLACK_EXPOSE_JSON

#include "slack.h"
#include "slack-log.h"
#include "slack-client.h"
#include "slack-rtm.h"

struct slack_reply {
	struct slack_reply *next;
	struct slack_reply *prev;
	json_t *json;
	int replyto;
};

struct slack_connect {
	/* Query parameters */
	const char *wsurl;			/*!< Entire WebSocket connection URL */
	const char *token;			/*!< Slack token */
	const char *gwserver;		/*!< Gateway server */
	const char *enterpriseid;	/*!< Enterprise ID (or NULL, for non-enterprise) */
	/* Header parameters */
	const char *cookies;		/*!< Entire cookie header */
	const char *cookie_d;		/*!< 'd' cookie (required for xoxc tokens) */
	const char *cookie_ds;		/*!< 'd_s' cookie (may also be required, in addition to d) */
};

struct slack_client {
	int msgid;				/*!< Current message ID for this connection */
	int fd;					/*!< Socket file descriptor */
	SSL *ssl;				/*!< SSL session */
	struct wss_client *ws;	/*!< WebSocket client */
	struct slack_callbacks *cb;
	void *userdata;			/*!< Custom user data */
	struct slack_reply replyhead;
	int listenpipe[2];		/*!< Listen pipe */
	int listeners;			/*!< Number of threads waiting for replies */
	pthread_mutex_t rdlock;	/*!< Mutex for reading */
	pthread_mutex_t wrlock;	/*!< Mutex for writing */
	struct slack_connect conn;
	char *reconnect_url;
	unsigned int autoreconnect:1;	/*!< Whether to autoreconnect */
	unsigned int exiting:1;			/*!< Have we been told to exit? */
	/* Current parsed message */
	const char *raw;		/*!< Raw message */
	json_t *json;			/*!< Parsed JSON */
	pthread_t thread;		/*!< Event loop thread */
};

static char root_certs_default[84] = "/etc/ssl/certs/ca-certificates.crt";
static const char *root_certs = root_certs_default;

void slack_set_tls_root_certs(const char *rootcerts)
{
	root_certs = rootcerts;
}

/*! \note Adapted from ssl_strerror, LBBS (GPLv2), but relicensed here under LGPL */
static const char *ssl_strerror(int err)
{
	switch (err) {
	case SSL_ERROR_NONE:
		return "SSL_ERROR_NONE";
	case SSL_ERROR_ZERO_RETURN:
		return "SSL_ERROR_ZERO_RETURN";
	case SSL_ERROR_WANT_READ:
		return "SSL_ERROR_WANT_READ";
	case SSL_ERROR_WANT_WRITE:
		return "SSL_ERROR_WANT_WRITE";
	case SSL_ERROR_WANT_CONNECT:
		return "SSL_ERROR_WANT_CONNECT";
	case SSL_ERROR_WANT_ACCEPT:
		return "SSL_ERROR_WANT_ACCEPT";
	case SSL_ERROR_WANT_X509_LOOKUP:
		return "SSL_ERROR_WANT_X509_LOOKUP";
	case SSL_ERROR_SYSCALL:
		return "SSL_ERROR_SYSCALL";
	case SSL_ERROR_SSL:
		return "SSL_ERROR_SSL";
	default:
		break;
	}
	return "Undefined";
}

static ssize_t __ssl_read(struct slack_client *slack, char *buf, size_t len)
{
	SSL *ssl = slack->ssl;
	ssize_t res = SSL_read(ssl, buf, len);
	if (res <= 0) {
		int sslerr = SSL_get_error(ssl, res);
		slack_debug(1, "SSL: %s\n", ssl_strerror(sslerr));
	}
	return res;
}

static ssize_t ssl_read(void *data, char *buf, size_t len)
{
	struct slack_client *slack = data;
	return __ssl_read(slack, buf, len);
}

static ssize_t __ssl_write(struct slack_client *slack, const char *buf, size_t len)
{
	SSL *ssl = slack->ssl;
	ssize_t res = SSL_write(ssl, buf, len);
	if (res <= 0) {
		int sslerr = SSL_get_error(ssl, res);
		slack_warning("SSL: %s\n", ssl_strerror(sslerr));
	}
	return res;
}

static ssize_t ssl_write(void *data, const char *buf, size_t len)
{
	struct slack_client *slack = data;
	return __ssl_write(slack, buf, len);
}

struct slack_client *slack_client_new(void *userdata)
{
	struct wss_client *ws;
	struct slack_client *slack = calloc(1, sizeof(*slack));

	slack->fd = -1;
	slack->listenpipe[0] = slack->listenpipe[1] = -1;

	if (pipe(slack->listenpipe)) {
		slack_fatal("Failed to create pipe: %s\n", strerror(errno));
		return NULL;
	}

	/* It's okay to pass in -1 for the file descriptor arguments,
	 * since we are using our own I/O callbacks anyways. */
	ws = wss_client_new(slack, -1, -1);
	if (!ws) {
		slack_fatal("Failed to create new WebSocket client\n");
		close(slack->listenpipe[0]);
		close(slack->listenpipe[1]);
		slack->listenpipe[0] = slack->listenpipe[1] = -1;
		return NULL;
	}

	wss_set_client_type(ws, WS_CLIENT); /* Client, not server */
	wss_set_io_callbacks(ws, ssl_read, ssl_write);

	if (!slack) {
		slack_fatal("Failed to allocate Slack session\n");
		close(slack->listenpipe[0]);
		close(slack->listenpipe[1]);
		slack->listenpipe[0] = slack->listenpipe[1] = -1;
		return NULL;
	}

	slack->userdata = userdata;
	slack->ws = ws;
	slack->msgid = 1; /* Must be positive, so start here */

	insque(&slack->replyhead, NULL);
	pthread_mutex_init(&slack->rdlock, NULL);
	pthread_mutex_init(&slack->wrlock, NULL);
	return slack;
}

void slack_client_set_autoreconnect(struct slack_client *slack, int enabled)
{
	/* Avoid errors trying to assign an int to a bit with certain compilation settings */
	if (enabled) {
		slack->autoreconnect = 1;
	} else {
		slack->autoreconnect = 0;
	}
}

void *slack_client_get_userdata(struct slack_client *slack)
{
	return slack->userdata;
}

static void slack_reply_free(struct slack_reply *reply)
{
	json_decref(reply->json);
	free(reply);
}

#define slack_rd_lock(slack) pthread_mutex_lock(&slack->rdlock)
#define slack_rd_unlock(slack) pthread_mutex_unlock(&slack->rdlock)
#define slack_wr_lock(slack) pthread_mutex_lock(&slack->wrlock)
#define slack_wr_unlock(slack) pthread_mutex_unlock(&slack->wrlock)

static void io_cleanup(struct slack_client *slack)
{
	struct slack_reply *reply;

	if (slack->ws) {
		wss_client_destroy(slack->ws);
		slack->ws = NULL;
	}
	if (slack->ssl) {
		SSL_free(slack->ssl);
		slack->ssl = NULL;
	}
	if (slack->fd != -1) {
		close(slack->fd);
		slack->fd = -1;
	}

	/* Not strictly required for I/O cleanup, but may as well since this should be cleared anyways if we're reconnecting */

	/* Empty the queue */
	slack_rd_lock(slack);
	reply = (&slack->replyhead)->next;
	while (reply) {
		struct slack_reply *next = reply->next;
		remque(reply);
		slack_reply_free(reply);
		reply = next;
	}
	slack_rd_unlock(slack);
}

void slack_client_destroy(struct slack_client *slack)
{
	io_cleanup(slack);

	if (slack->listenpipe[0] != -1) {
		close(slack->listenpipe[0]);
		close(slack->listenpipe[1]);
		slack->listenpipe[0] = slack->listenpipe[1] = -1;
	}

	if (slack->reconnect_url) {
		free(slack->reconnect_url);
	}

	pthread_mutex_destroy(&slack->rdlock);
	pthread_mutex_destroy(&slack->wrlock);
	free(slack);
}

/*! \note Adapted from bbs_tcp_connect, LBBS (GPLv2), but relicensed here under LGPL */
static int slack_connect(const char *hostname, int port)
{
	char ip[256];
	int e;
	struct addrinfo hints, *res, *ai;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	struct sockaddr_in *saddr_in; /* IPv4 */
	struct sockaddr_in6 *saddr_in6; /* IPv6 */
	int sfd = -1;
	struct timeval timeout;
	int lport = 0;

	/* Resolve the hostname */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* TCP */

	e = getaddrinfo(hostname, NULL, &hints, &res);
	if (e) {
		slack_fatal("getaddrinfo (%s): %s\n", hostname, gai_strerror(e));
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			saddr_in = (struct sockaddr_in *) ai->ai_addr;
			saddr_in->sin_port = htons((uint16_t) port);
			inet_ntop(ai->ai_family, &saddr_in->sin_addr, ip, sizeof(ip)); /* Print IPv4*/
		} else if (ai->ai_family == AF_INET6) {
			saddr_in6 = (struct sockaddr_in6 *) ai->ai_addr;
			saddr_in6->sin6_port = htons((uint16_t) port);
			inet_ntop(ai->ai_family, &saddr_in6->sin6_addr, ip, sizeof(ip)); /* Print IPv6 */
		}
		sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sfd == -1) {
			slack_error("socket: %s\n", strerror(errno));
			continue;
		}
		slack_debug(3, "Attempting connection to %s:%d\n", ip, port);
		/* Put the socket in nonblocking mode to prevent connect from blocking for a long time.
		 * Using SO_SNDTIMEO works on Linux and is easier than doing bbs_unblock_fd before and bbs_block_fd after. */
		timeout.tv_sec = 4; /* Wait up to 4 seconds to connect */
		timeout.tv_usec = 0;
		setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		if (connect(sfd, ai->ai_addr, ai->ai_addrlen)) {
			slack_error("connect: %s\n", strerror(errno));
			close(sfd);
			sfd = -1;
			continue;
		}
		break; /* Use the 1st one that works */
	}

	freeaddrinfo(res);
	if (sfd == -1) {
		return -1;
	} else {
		timeout.tv_sec = 0; /* Change back to fully blocking */
		setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	}

	/* Figure out what port we're using locally for this connection */
	if (getsockname(sfd, (struct sockaddr *) &sin, &slen)) {
		slack_warning("getsockname failed: %s\n", strerror(errno));
	} else {
		lport = ntohs(sin.sin_port);
	}

	slack_debug(1, "Connected to %s:%d using port %d\n", hostname, port, lport);
	return sfd;
}

/*! \note Adapted from ssl_client_new, LBBS (GPLv2), but relicensed here under LGPL */
static SSL *slack_client_ssl_init(int fd, const char *snihostname)
{
	SSL *ssl;
	SSL_CTX *ctx;
	X509 *server_cert;
	long verify_result;
	char *str;

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		slack_error("Failed to setup new SSL context\n");
		return NULL;
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3); /* Only use TLS */
	ssl = SSL_new(ctx);
	if (!ssl) {
		slack_error("Failed to create new SSL\n");
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (SSL_set_fd(ssl, fd) != 1) {
		slack_error("Failed to connect SSL: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto sslcleanup;
	}

	/* Attempt to verify the server's TLS certificate.
	 * If we don't do this, verify_result won't be set properly later on. */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 4);
	if (SSL_CTX_load_verify_locations(ctx, root_certs, NULL) != 1) {
		slack_error("Failed to load root certs from %s: %s\n", root_certs, ERR_error_string(ERR_get_error(), NULL));
		goto sslcleanup;
	}

	/* SNI (Server Name Indication) tells the server which host we want.
	 * Some servers may host multiple hosts at the same IP,
	 * and won't send us a TLS certificate if we don't provide the SNI.
	 * Either way, we should always send SNI if possible. */
	if (SSL_set_tlsext_host_name(ssl, snihostname) != 1) {
		slack_error("Failed to set SNI for TLS connection\n");
	}

connect:
	if (SSL_connect(ssl) == -1) {
		int sslerr = SSL_get_error(ssl, -1);
		if (sslerr == SSL_ERROR_WANT_READ) {
			usleep(1000);
			goto connect;
		}
		slack_error("SSL error: %s\n", ssl_strerror(sslerr));
		slack_error("Failed to connect SSL: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto sslcleanup;
	}
	/* Verify cert */
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
	server_cert = SSL_get1_peer_certificate(ssl);
#else
	server_cert = SSL_get_peer_certificate(ssl);
#endif
	if (!server_cert) {
		slack_error("Failed to get peer certificate\n");
		goto sslcleanup;
	}
	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	if (!str) {
		slack_error("Failed to get peer certificate\n");
		goto sslcleanup;
	}
	slack_debug(8, "TLS SN: %s\n", str);
	OPENSSL_free(str);
	str = X509_NAME_oneline(X509_get_issuer_name (server_cert), 0, 0);
	if (!str) {
		slack_error("Failed to get peer certificate\n");
		goto sslcleanup;
	}
	slack_debug(8, "TLS Issuer: %s\n", str);
	OPENSSL_free(str);
	X509_free(server_cert);
	verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		slack_warning("SSL verify failed: %ld (%s)\n", verify_result, X509_verify_cert_error_string(verify_result));
		goto sslcleanup;
	} else {
		slack_debug(4, "TLS verification successful\n");
	}

	SSL_CTX_free(ctx);
	return ssl;

sslcleanup:
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	ctx = NULL;
	ssl = NULL;
	return NULL;
}

#define STRLEN(s) ( (sizeof(s)/sizeof(s[0])) - sizeof(s[0]) )
#define SSL_SEND(slack, data) SSL_write(slack->ssl, data, STRLEN(data))

#define SLACK_WS_HOSTNAME "wss-primary.slack.com"
#define START_ARGS "%3Fagent%3Dclient%26org_wide_aware%3Dtrue%26agent_version%3D1688756872%26eac_cache_ts%3Dtrue%26cache_ts%3D0%26name_tagging%3Dtrue%26only_self_subteams%3Dtrue%26connect_only%3Dtrue%26ms_latest%3Dtrue"

static int websocket_handshake(struct slack_client *slack, struct slack_connect *conn)
{
	char buf[4096];
	char urlbuf[1024];
	const char *url = conn->wsurl;
	int res;
	size_t bytes_read = 0;

	/* Poor man's HTTP request. It gets the job done.
	 * After the upgrade is complete, the WebSocket library handles all the data on the wire. */

	if (conn->wsurl) {
		/* Some minor sanity checks */
		if (conn->wsurl[0] != '/') {
			slack_error("Invalid Slack WebSocket URL (must begin with '/')\n");
			return -1;
		}
	} else {
		snprintf(urlbuf, sizeof(urlbuf), "/?token=%s&sync_desync=1&slack_client=desktop&start_args=%s&no_query_on_subscribe=1&flannel=3&lazy_channels=1&gateway_server=%s&enterprise_id=%s&batch_presence_aware=1", conn->token, START_ARGS, conn->gwserver, conn->enterpriseid ? conn->enterpriseid : "");
		url = urlbuf;
	}
	res = snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\n", url);
	__ssl_write(slack, buf, res);

	SSL_SEND(slack, "Host: " SLACK_WS_HOSTNAME "\r\n");
	SSL_SEND(slack, "Pragma: no-cache\r\n");
	SSL_SEND(slack, "Cache-Control: no-cache\r\n");

	if (conn->cookies) {
		res = snprintf(buf, sizeof(buf), "Cookie: %s\r\n", conn->cookies);
		__ssl_write(slack, buf, res);
	} else if (conn->cookie_d) {
		if (conn->cookie_ds) {
			res = snprintf(buf, sizeof(buf), "Cookie: d=%s; d-s=%s\r\n", conn->cookie_d, conn->cookie_ds);
		} else {
			res = snprintf(buf, sizeof(buf), "Cookie: d=%s\r\n", conn->cookie_d);
		}
		__ssl_write(slack, buf, res);
	}

	SSL_SEND(slack, "Connection: Upgrade\r\n");
	SSL_SEND(slack, "Upgrade: websocket\r\n");
	SSL_SEND(slack, "Origin: https://app.slack.com\r\n");
	SSL_SEND(slack, "Sec-WebSocket-Version: 13\r\n");
	SSL_SEND(slack, "Accept-Language: en-US,en;q=0.9\r\n");
	/* Use a fixed key for simplicity */
	SSL_SEND(slack, "Sec-WebSocket-Key: 6+2pfR0fnsCpRevdvGNNfQ==\r\n");
	SSL_SEND(slack, "\r\n");

	/* Ideally we would read line by line until we are done receiving the headers (but no further).
	 * This is a kludge to avoid further dependencies. */
	for (;;) {
		if (bytes_read >= sizeof(buf) - 1) {
			return -1;
		}
		res = ssl_read(slack, &buf[bytes_read], 1);
		if (res < 1) {
			slack_error("Handshake failed(%lu): '%.*s'\n", bytes_read, (int) bytes_read, buf);
			return -1;
		}
		bytes_read += res;
		if (memmem(buf, bytes_read, "\r\n\r\n", 4)) {
			buf[bytes_read] = '\0';
			break; /* Got end of response headers */
		}
	}

	if (!strstr(buf, "HTTP/1.1 101")) { /* Wrong HTTP response code */
		slack_error("Didn't receive 101 Switching Protocols: %s\n", buf);
		return -1;
	} else if (!strcasestr(buf, "sec-websocket-accept: uOu0f8bOA3tlMfD1zeIdGuncti8=")) { /* Not a WebSocket server? */
		slack_error("WebSocket upgrade failed: %s\n", buf);
		return -1;
	}

	return 0;
}

void slack_client_set_connect_url(struct slack_client *slack, const char *url)
{
	struct slack_connect *conn = &slack->conn;
	conn->wsurl = url;
}

void slack_client_set_token(struct slack_client *slack, const char *token)
{
	struct slack_connect *conn = &slack->conn;
	conn->token = token;
}

void slack_client_set_gateway_server(struct slack_client *slack, const char *gwserver)
{
	struct slack_connect *conn = &slack->conn;
	conn->gwserver = gwserver;
}

void slack_client_set_enterprise_id(struct slack_client *slack, const char *entid)
{
	struct slack_connect *conn = &slack->conn;
	conn->enterpriseid = entid;
}

void slack_client_set_cookies(struct slack_client *slack, const char *cookies)
{
	struct slack_connect *conn = &slack->conn;
	conn->cookies = cookies;
}

void slack_client_set_cookie(struct slack_client *slack, const char *name, const char *value)
{
	struct slack_connect *conn = &slack->conn;
	if (!strcmp(name, "d")) {
		conn->cookie_d = value;
	} else if (!strcmp(name, "d-s")) {
		conn->cookie_ds = value;
	} else {
		slack_debug(1, "Ignoring unneeded cookie '%s'\n", name);
	}
}

int slack_client_connect_possible(struct slack_client *slack)
{
	struct slack_connect *conn = &slack->conn;
	if (!conn->token) {
		slack_debug(1, "Missing token\n");
		return 0;
	}
	if (!conn->cookie_d && !strncmp(conn->token, "xoxc", 4)) {
		slack_debug(1, "Cookie required for xoxc tokens\n");
		return 0;
	}
	return 1;
}

int slack_client_connect(struct slack_client *slack)
{
	if (!slack_client_connect_possible(slack)) {
		return -1;
	}
	/* Establish the TCP connection */
	slack->fd = slack_connect(SLACK_WS_HOSTNAME, 443);
	if (slack->fd == -1) {
		return -1;
	}
	/* Set up the TLS layer */
	slack->ssl = slack_client_ssl_init(slack->fd, SLACK_WS_HOSTNAME);
	if (!slack->ssl) {
		return -1;
	}
	/* Make an HTTP request and perform the WebSocket upgrade */
	if (websocket_handshake(slack, &slack->conn)) {
		return -1;
	}
	return 0;
}

#define WAIT_FOR_REPLIES

#ifdef WAIT_FOR_REPLIES
#define slack_send_and_wait(client, msgid, msg) slack_send(client, msgid, msg, strlen(msg), 1)
#else
#define slack_send_and_wait(client, msgid, msg) slack_send(client, msgid, msg, strlen(msg), 0)
#endif

#define slack_send_nowait(client, msg) slack_send(client, 0, msg, strlen(msg), 0)

/* Forward declaration */
static struct slack_reply *slack_send(struct slack_client *client, int msgid, const char *msg, size_t len, int expect_response);

static int slack_read(struct slack_client *slack, struct slack_callbacks *cb)
{
	int res;
	struct wss_client *ws = slack->ws;

	res = wss_read(ws, 5000, 1); /* Pass in 1 since we already know poll returned activity for this fd */
	if (res < 0) {
		slack_debug(1, "Failed to read WebSocket frame\n"); /* Usually indicates the event loop was interrupted (slack_client_interrupt) */
		if (wss_error_code(ws)) {
			wss_close(ws, wss_error_code(ws));
		} /* else, if client already closed, don't try writing any further */
		return -1;
	} else if (res > 0) {
		struct wss_frame *frame = wss_client_frame(ws);
		slack_debug(8, "WebSocket '%s' frame received\n", wss_frame_name(frame));
		switch (wss_frame_opcode(frame)) {
			case WS_OPCODE_TEXT:
				slack_parse_message(cb, slack, wss_frame_payload(frame), wss_frame_payload_length(frame));
				break;
			case WS_OPCODE_BINARY:
				/* Do something... */
				slack_warning("Ignoring received binary frame\n");
				return -1;
			case WS_OPCODE_CLOSE:
				/* Close the connection and break */
				slack_debug(1, "Server closed WebSocket connection (code %d)\n", wss_close_code(frame));
				wss_close(ws, WS_CLOSE_NORMAL);
				wss_frame_destroy(frame);
				return -1;
			case WS_OPCODE_PING:
				/* Reply in kind with a pong containing the same payload */
				wss_write(ws, WS_OPCODE_PONG, wss_frame_payload(frame), wss_frame_payload_length(frame));
				break;
			case WS_OPCODE_PONG:
				/* Ignore */
				break;
			default:
				slack_warning("Unexpected WS opcode %d?\n", wss_frame_opcode(frame));
		}
		wss_frame_destroy(frame);
	}
	return 0;
}

static int slack_get_next_msgid(struct slack_client *slack)
{
	int msgid = slack->msgid++; /* Not thread safe, if the caller needs thread safety, additional locking must be provided by the application */
	return msgid;
}

static int send_and_wait(struct slack_client *slack, int msgid, char *msg)
{
	struct slack_reply *reply;

	reply = slack_send_and_wait(slack, msgid, msg);
	free(msg);
	if (reply) {
		slack_reply_free(reply);
	} else {
#ifdef WAIT_FOR_REPLIES
		slack_error("Failed to receive response to request %d\n", msgid);
		return -1;
#endif
	}

	return 0;
}

int slack_channel_post_message(struct slack_client *slack, const char *channel, const char *thread_ts, const char *text)
{
	int msgid;
	char *msg;

	msgid = slack_get_next_msgid(slack);
	msg = slack_channel_construct_message(msgid, channel, thread_ts, text);
	if (!msg) {
		return -1;
	}
	return send_and_wait(slack, msgid, msg);
}

int slack_channel_indicate_typing(struct slack_client *slack, const char *channel, const char *thread_ts)
{
	int msgid;
	char *msg;

	msgid = slack_get_next_msgid(slack);
	msg = slack_channel_construct_typing(msgid, channel, thread_ts);
	if (!msg) {
		return -1;
	}
	return send_and_wait(slack, msgid, msg);
}

static int slack_channel_ping(struct slack_client *slack)
{
	int msgid;
	char *msg;

	msgid = slack_get_next_msgid(slack);
	msg = slack_construct_ping(msgid);
	if (!msg) {
		return -1;
	}
	return send_and_wait(slack, msgid, msg);
}

int slack_users_presence_query(struct slack_client *slack, json_t *userids)
{
	char *msg;

	msg = slack_users_construct_presence_query(userids);
	if (!msg) {
		return -1;
	}
	slack_send_nowait(slack, msg);
	free(msg);
	return 0;
}

int slack_users_presence_subscribe(struct slack_client *slack, json_t *userids)
{
	char *msg;

	msg = slack_users_construct_presence_subscription(userids);
	if (!msg) {
		return -1;
	}
	slack_send_nowait(slack, msg);
	free(msg);
	return 0;
}

static int on_reply(struct slack_event *event)
{
#ifdef WAIT_FOR_REPLIES
	struct slack_reply *reply;
	json_t *json;
	char c;
	int res;
	struct slack_client *slack = slack_event_get_userdata(event);

	/* Once the callback returns, data will no longer be a valid reference,
	 * so might as well just parse (or reparse) it to JSON now */
	json = json_deep_copy(slack_event_get_json(event));
	if (!json) {
		slack_error("Failed to duplicate JSON string: %s\n", slack_event_get_raw(event));
		return -1;
	}

	reply = calloc(1, sizeof(*reply));
	if (!reply) {
		slack_fatal("Failed to receive reply\n"); /* This is bad, if we never received a reply we might be blocked waiting on */
		json_decref(json);
		return -1;
	}

	reply->json = json;
	reply->replyto = json_number_value(json_object_get(json, "reply_to"));

	/* Insert into queue */
	slack_rd_lock(slack);
	insque(reply, &slack->replyhead);
	slack_rd_unlock(slack);

	/* Signal all listeners */
	c = 0;
	res = write(slack->listenpipe[1], &c, 1);
	if (res <= 0) {
		slack_warning("write failed: %s\n", strerror(errno));
		return -1;
	}
#else
	(void) slack;
	(void) data;
	(void) userdata;
	(void) len;
#endif
	return 0;
}

static int on_reconnect_url(struct slack_event *event, const char *url)
{
	struct slack_client *slack = slack_event_get_userdata(event);
	if (slack->autoreconnect) {
		if (slack->reconnect_url) {
			free(slack->reconnect_url);
		}
		slack->reconnect_url = strdup(url);
	}
	return 0;
}

#define SLACK_PING_INTERVAL 30000 /* Slack wants clients to ping them frequently */

void slack_event_loop(struct slack_client *slack, struct slack_callbacks *cb)
{
	struct pollfd pfd;
	int res;
	time_t lastconnect;

	pfd.fd = slack->fd;
	pfd.events = POLLIN;

	slack->cb = cb;
	slack->cb->reply = on_reply;
	if (slack->autoreconnect) {
		slack->cb->reconnect_url = on_reconnect_url;
	}
	slack->thread = pthread_self();

	lastconnect = time(NULL);

	for (;;) {
		pfd.revents = 0;
		res = poll(&pfd, 1, SLACK_PING_INTERVAL);
		if (res < 0) {
			if (errno = EINTR) {
				continue;
			}
			/* Possibly program exit (interrupt) */
			slack_debug(1, "poll failed: %s\n", strerror(errno));
			break;
		}
		if (pfd.revents) {
			if (slack_read(slack, slack->cb)) {
				time_t now;
				if (slack->exiting || !slack->autoreconnect || !slack->reconnect_url) {
					break;
				}
				slack_client_set_connect_url(slack, slack->reconnect_url);
				now = time(NULL);
				if (lastconnect > now - 300) {
					/* Prevent reconnecting too quickly if disconnected.
					 * This is only for long lived periodic disconnects */
					slack_warning("Unable to autoreconnect, too soon since last connect\n");
					break;
				}
				slack_debug(1, "Disconnected prematurely, attempting reconnect...\n");
				io_cleanup(slack);
				if (slack_client_connect(slack)) {
					slack_warning("Automatic reconnect failed\n");
					break;
				}
				lastconnect = now;
			}
		} else {
			/* Send Slack a ping */
			if (slack_channel_ping(slack)) {
				break;
			}
		}
	}
}

void slack_client_interrupt(struct slack_client *slack)
{
	if (!slack) {
		slack_error("No client provided to interrupt\n");
		return;
	}
	slack->exiting = 1;
	shutdown(slack->fd, SHUT_RDWR);
	return;
}

static struct slack_reply *slack_send(struct slack_client *slack, int msgid, const char *msg, size_t len, int expect_response)
{
	int res;
	struct pollfd pfds[2];
	time_t started = 0;
	nfds_t numfds = 0;

	/* slack->cb could be NULL, if the event loop hasn't been started yet.
	 * This isn't an issue, we won't process any events until the event loop starts anyways.
	 * Only at that point will we receive events and actually need the callbacks. */

	if (!msg) {
		/* Allocation failed prior to calling slack_write? */
		slack_error("Can't write NULL message\n");
		return NULL;
	}

	if (len > 16 * 1024) {
		/* https://api.slack.com/rtm#limits
		 * Maximum is 16 KB, and messages set to channels should be under 4,000 characters */
		slack_error("Message too long for Slack RTM API: %lu bytes\n", len);
		return NULL;
	}

	slack_debug(6, "==> [%d] %.*s\n", msgid, (int) len, msg);

	/* wss_write is not multithread safe, we must surround it with our own lock */
	slack_wr_lock(slack);
	slack->listeners++;
	res = wss_write(slack->ws, WS_OPCODE_TEXT, msg, len);
	slack_wr_unlock(slack);

	if (res) {
		slack_error("Failed to write WebSocket frame\n");
		return NULL;
	}

	if (!expect_response) {
		slack_debug(7, "No response expected\n");
		return NULL;
	}

#define REPLY_TIMEOUT 10

	/* This must be fully decoupled from reading frames, to avoid possibilities of deadlock. */
	pfds[0].fd = slack->listenpipe[0];
	pfds[0].events = POLLIN;
	numfds = 1;

	/* If this is a ping (called by event loop thread), we also need to read event as usual
	 * in order to receive the reply. */
	if (slack->thread == pthread_self()) {
		numfds++;
		pfds[1].fd = slack->fd;
		pfds[1].events = POLLIN;
	}

	for (;;) {
		struct slack_reply *reply;
		char c;
		int pres;
		if (!started) {
			started = time(NULL);
		} else {
			time_t now = time(NULL);
			if (now > started + REPLY_TIMEOUT) {
				slack_warning("Failed to receive reply for message %d after %ld seconds\n", msgid, now - started);
				return NULL;
			}
		}
		slack_debug(8, "Still waiting for a response to %d...\n", msgid);
		pfds[0].revents = pfds[1].revents = 0;
		pres = poll(pfds, numfds, REPLY_TIMEOUT * 1000); /* Wait up to 5 seconds for a reply */
		if (pres <= 0) {
			slack_warning("Failed to receive reply for message %d, poll returned %d: %s\n", msgid, pres, strerror(errno));
			return NULL;
		}
		if (pfds[0].revents) {
			slack_rd_lock(slack);
			/* Check the reply queue for our reply.
			 * If it's for us, read from the listen pipe.
			 * If not, don't, it's somebody else's. */
			reply = &slack->replyhead;
			while ((reply = reply->next)) {
				if (reply->replyto == msgid) {
					break;
				}
			}
			if (!reply) {
				slack_debug(7, "Didn't find reply to message %d yet...\n", msgid);
				continue;
			}
			slack_wr_lock(slack);
			remque(reply);
			slack->listeners--;
			slack_wr_unlock(slack);
			pres = read(slack->listenpipe[0], &c, 1);
			if (pres <= 0) {
				slack_warning("Failed to read from pipe for message %d, read returned %d: %s\n", msgid, pres, strerror(errno));
			}
			slack_rd_unlock(slack);
			slack_debug(7, "Successfully received reply to message %d\n", reply->replyto);
			return reply;
		} else if (pfds[1].revents) {
			slack_read(slack, slack->cb);
		}
	}
}
