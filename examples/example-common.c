/*
 * libslackrtm examples -- Client library for Slack RTM
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*! \file
 *
 * \brief Common functions for examples
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>

#include <slackrtm/slack.h>
#include <slackrtm/slack-client.h>

#include "example-common.h"

static void slack_log(int level, int len, const char *file, const char *function, int line, const char *buf)
{
	switch (level) {
		case SLACK_LOG_FATAL:
		case SLACK_LOG_ERROR:
		case SLACK_LOG_WARNING:
			fprintf(stderr, "%s:%d %s(): %.*s", file, line, function, len, buf);
			break;
		case SLACK_LOG_DEBUG:
		default: /* Debug consists of multiple levels */
			fprintf(stderr, "%s:%d %s(): %.*s", file, line, function, len, buf);
	}
}

static int debug_level = 0;
static const char *gwserver = NULL;
static const char *token = NULL;
static const char *cookie = NULL;

static void option_help(void)
{
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "-c [cookie]    - Contents of d cookie (URL encoded)\n");
	fprintf(stderr, "-d             - Increase debug level\n");
	fprintf(stderr, "-h             - Show usage\n");
	fprintf(stderr, "-r             - Relay channel\n");
	fprintf(stderr, "-s [gwserver]  - Gateway server ID\n");
	fprintf(stderr, "-t [token]     - User token\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Some options can also or only be set using environment variables:\n");
	fprintf(stderr, "SLACK_TOKEN        - User token\n");
	fprintf(stderr, "SLACK_GWSERVER     - Gateway server ID\n");
	fprintf(stderr, "SLACK_ENTERPRISE   - Enterprise ID\n");
	fprintf(stderr, "SLACK_WS_URL       - Raw WebSocket request URI to send\n");
	fprintf(stderr, "SLACK_COOKIE_D     - Contents of d cookie (URL encoded)\n");
	fprintf(stderr, "SLACK_COOKIE_D_S   - Contents of d-s cookie\n");
	fprintf(stderr, "SLACK_COOKIES      - Raw cookie header value to send\n");
}

int parse_option(int argc, char *argv[], int c)
{
	switch (c) {
		case 'c':
			cookie = argv[optind++];
			break;
		case 'd':
			debug_level++;
			break;
		case 'h':
			option_help();
			return -1;
		case 's':
			gwserver = argv[optind++];
			break;
		case 't':
			token = argv[optind++];
			break;
		default:
			fprintf(stderr, "Unknown option: '%c'\n", c);
			return -1;
	}
	return 0;
}

static int parse_options(int argc, char *argv[])
{
	static const char *getopt_settings = COMMON_OPTIONS;
	int c;

	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		if (parse_option(argc, argv, c)) {
			return -1;
		}
	}

	return 0;
}

static struct slack_client *active = NULL;

static void sigint_handler(int sig)
{
	(void) sig;
	if (active) {
		slack_client_interrupt(active);
	}
}

int slack_example_run(int argc, char *argv[], struct slack_callbacks *cb)
{
	struct slack_client *slack;

	if (parse_options(argc, argv)) {
		return -1;
	}

	/* Check environment variables */
	if (!token) {
		token = getenv("SLACK_TOKEN");
	}
	if (!gwserver) {
		gwserver = getenv("SLACK_GWSERVER");
	}
	if (!cookie) {
		cookie = getenv("SLACK_COOKIE_D");
	}

	if (!gwserver) {
		fprintf(stderr, "Missing gateway server (-h for usage)\n");
		return -1;
	} else if (!token) {
		fprintf(stderr, "Missing token (-h for usage)\n");
		return -1;
	} else if (!cookie && !strncmp(token, "xoxc", 4)) { /* A cookie is required for these tokens */
		fprintf(stderr, "Missing cookie (-h for usage)\n");
		return -1;
	}

	/* Initialize the library */
	slack_set_logger(slack_log);
	slack_set_log_level(SLACK_LOG_DEBUG + debug_level);

	/* Create a Slack client using the high-level APIs */
	slack = slack_client_new(NULL);
	if (!slack) {
		fprintf(stderr, "Failed to create Slack client\n");
		goto cleanup;
	}

	/* If these are NULL, it doesn't hurt anything */
	slack_client_set_enterprise_id(slack, getenv("SLACK_ENTERPRISE"));
	slack_client_set_connect_url(slack, getenv("SLACK_WS_URL"));
	slack_client_set_cookies(slack, getenv("SLACK_COOKIES"));
	slack_client_set_cookie(slack, "d-s", getenv("SLACK_COOKIE_D_S"));

	if (token) {
		slack_client_set_token(slack, token);
	}
	if (gwserver) {
		slack_client_set_gateway_server(slack, gwserver);
	}
	if (cookie) {
		slack_client_set_cookie(slack, "d", cookie);
	}

	if (!slack_client_connect_possible(slack)) {
		fprintf(stderr, "Some required arguments are missing: either use environmental variables or command line arguments\n");
		goto cleanup;
	}

	/* Connect to Slack */
	if (slack_client_connect(slack)) {
		fprintf(stderr, "Slack client connection failed\n");
		goto cleanup;
	}

	fprintf(stderr, "Connected to Slack, starting event loop...\n");

	/* Run the event loop */
	active = slack;
	signal(SIGINT, sigint_handler);
	slack_event_loop(slack, cb);
	signal(SIGINT, NULL);
	active = NULL;

cleanup:
	slack_client_destroy(slack);
	return 0;
}
