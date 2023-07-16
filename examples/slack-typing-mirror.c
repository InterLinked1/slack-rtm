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
 * \brief Appear to be typing in a channel whenever anyone else is typing
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stddef.h>
#include <stdio.h>

#include <slackrtm/slack.h>
#include <slackrtm/slack-client.h>

#include "example-common.h"

static int user_typing(struct slack_event *event, const char *channel, int id, const char *user)
{
	struct slack_client *slack = slack_event_get_userdata(event);

	fprintf(stderr, "=== Someone is typing! %d: %s/%s\n", id, channel, user);

	/* You're typing something? Me too! */
	if (slack_channel_indicate_typing(slack, channel)) {
		fprintf(stderr, "=== Failed to indicate typing to channel %s\n", channel);
	}

	return 0;
}

struct slack_callbacks slack_callbacks = {
	.user_typing = user_typing,
};

int main(int argc, char *argv[])
{
	return slack_example_run(argc, argv, &slack_callbacks);
}
