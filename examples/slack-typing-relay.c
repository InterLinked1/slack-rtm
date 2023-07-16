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
 * \brief Notify members of a specified channel whenever anyone in any (other) channel is typing
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stddef.h>
#include <stdio.h>
#include <getopt.h>

#include <slackrtm/slack.h>
#include <slackrtm/slack-client.h>

#include "example-common.h"

static const char *relaychan = NULL;

static int user_typing(struct slack_event *event, const char *channel, int id, const char *user)
{
	char msg[256];
	struct slack_client *slack = slack_event_get_userdata(event);

	fprintf(stderr, "=== Someone is typing! %d: %s/%s\n", id, channel, user);

	/* Translates @channel and @user, and #channel link, appropriately */
	snprintf(msg, sizeof(msg), "<!channel> Looks like <@%s> just started typing in channel <#%s>", user, channel);

	/* Whenever somebody starts typing, post a message to the channel */
	if (slack_channel_post_message(slack, relaychan, msg)) {
		fprintf(stderr, "=== Failed to post message to channel %s\n", channel);
	}

	return 0;
}

struct slack_callbacks slack_callbacks = {
	.user_typing = user_typing,
};

static int parse_custom_options(int argc, char *argv[])
{
	static const char *getopt_settings = COMMON_OPTIONS "r";
	int c;

	/* slack_example_run will check the other options */
	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case 'r':
			relaychan = argv[optind++];
			break;
		default:
			if (parse_option(argc, argv, c)) {
				return -1;
			}
			break;
		}
	}

	if (!relaychan) {
		fprintf(stderr, "Missing relay channel argument (-h for usage)\n");
		return -1;
	} else if (!slack_valid_channel_id(relaychan)) {
		/* You didn't really just use the channel *name*, did you? */
		fprintf(stderr, "Invalid channel ID: %s\n", relaychan);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	if (parse_custom_options(argc, argv)) {
		return -1;
	}
	return slack_example_run(argc, argv, &slack_callbacks);
}
