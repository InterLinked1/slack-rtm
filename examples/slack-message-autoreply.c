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

static int on_message(struct slack_event *event, const char *channel, const char *thread_ts, const char *ts, const char *user, const char *text)
{
	char msg[256];
	struct slack_client *slack = slack_event_get_userdata(event);

	(void) ts;

	fprintf(stderr, "=== Someone posted a message! %s/%s: %s\n", channel, user, text);

	if (thread_ts) {
		return 0; /* Don't reply to messages that are part of a thread */
	}

	/* Translates @user appropriately */
	snprintf(msg, sizeof(msg), "<@%s> Thank you for sharing! Hope you have a great rest of your day!", user);

	/* We MUST have a mechanism to prevent reply loops, or we'll also see the reply we post below,
	 * and autorespond to that... and so on and so forth.
	 * One option is to not reply to anything from this user.
	 * Here, we don't reply to anything that's in a thread, and since we reply in thread, we can't reply to ourself.
	 * The right mechanism will depend on your application, but you must have one,
	 * or you'll probably get rate-limited pretty quickly. */

	/* Post a response to the message, in thread */
	if (slack_channel_post_message(slack, channel, ts, msg)) {
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
