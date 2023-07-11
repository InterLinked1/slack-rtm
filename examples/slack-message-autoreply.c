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
 * \brief Autoreply to any message posted in a channel
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <slackrtm/slack.h>
#include <slackrtm/slack-client.h>

#include "example-common.h"

static int on_message(struct slack_client *slack, void *userdata, const char *channel, const char *user, const char *text, const char *raw)
{
	char msg[256];

	(void) userdata;
	(void) raw;

	fprintf(stderr, "=== Someone posted a message! %s/%s: %s\n", channel, user, text);

	/* Translates @user appropriately */
	snprintf(msg, sizeof(msg), "<@%s> Thank you for sharing! Hope you have a great rest of your day!", user);

	if (strstr(text, msg)) {
		/* We MUST have a mechanism to prevent reply loops, or we'll also see the reply we post below,
		 * and autorespond to that... and so on and so forth.
		 * One option is to not reply to anything from this user.
		 * Here, we don't reply to anything containing the autoreply message.
		 * The right mechanism will depend on your application, but you must have one,
		 * or you'll probably get rate-limited pretty quickly. */
		fprintf(stderr, "Not responding to our autoresponse\n");
		return 0;
	}

	/* Post a response to the message */
	if (slack_channel_post_message(slack, channel, msg)) {
		fprintf(stderr, "=== Failed to post message to channel %s\n", channel);
	}

	return 0;
}

struct slack_callbacks slack_callbacks = {
	.message = on_message,
};

int main(int argc, char *argv[])
{
	return slack_example_run(argc, argv, &slack_callbacks);
}
