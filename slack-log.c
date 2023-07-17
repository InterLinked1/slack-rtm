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
 * \brief Internal logging
 *
 * \note See also: https://api.slack.com/rtm
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define _GNU_SOURCE 1 /* asprintf */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include <wss.h> /* libwss */

/* Use relative path instead of system path for the library itself */
#include "slack.h"
#include "slack-log.h"

static void (*logger_cb)(int level, int bytes, const char *file, const char *function, int line, const char *msg) = NULL;
static int loglevel = SLACK_LOG_NONE;

void __attribute__ ((format (printf, 5, 6))) slack_log(int level, const char *file, const char *function, int line, const char *fmt, ...)
{
	va_list ap;
	int len;
	char *buf;

	if (level > loglevel) {
		return;
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return;
	}

	if (logger_cb) {
		logger_cb(level, len, file, function, line, buf);
	} else {
		/* Log to STDERR */
		int res = write(STDERR_FILENO, buf, len);
		(void) res;
	}
	free(buf);
}

#ifdef WEBSOCKET_DEBUG
static void ws_log(int level, int len, const char *file, const char *function, int line, const char *buf)
{
	switch (level) {
		case WS_LOG_ERROR:
			slack_log(SLACK_LOG_ERROR, file, function, line, "%.*s", len, buf);
			break;
		case WS_LOG_WARNING:
			slack_log(SLACK_LOG_WARNING, file, function, line, "%.*s", len, buf);
			break;
		case WS_LOG_DEBUG:
		default: /* Debug consists of multiple levels */
			slack_log(level - SLACK_LOG_DEBUG + 5, file, function, line, "%.*s", len, buf);
	}
}
#endif

void slack_set_logger(void (*logger)(int level, int bytes, const char *file, const char *function, int line, const char *msg))
{
	logger_cb = logger;
}

void slack_set_log_level(int level)
{
#ifdef WEBSOCKET_DEBUG
	/* In case the wss library is being used in a program that also uses it for something else,
	 * don't use these callbacks unless we really have to */
	if (level) {
		wss_set_logger(ws_log);
		wss_set_log_level(WS_LOG_DEBUG + 5);
	}
#endif
	loglevel = level;
}
