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
 * \brief Client library for Slack RTM (Real Time Messaging) - low-level APIs
 *
 * \note See also: https://api.slack.com/rtm
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define _GNU_SOURCE 1 /* asprintf */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <jansson.h>

#define SLACK_EXPOSE_JSON

/* Use relative path instead of system path for the library itself */
#include "slack.h"
#include "slack-log.h"
#include "slack-rtm.h"

struct slack_event {
	void *userdata;					/*!< User data provided during slack_client_new, NULL if no user data or no client in use */
	json_t *json;					/*!< Pointer to parsed json_t. Cast to (json_t*) to use. */
	const char *raw;				/*!< Raw event text */
	size_t rawlen;					/*!< Length of raw event text */
};

void *slack_event_get_userdata(struct slack_event *event)
{
	return event->userdata;
}

const json_t *slack_event_get_json(struct slack_event *event)
{
	return event->json;
}

const char *slack_event_get_raw(struct slack_event *event)
{
	return event->raw;
}

size_t slack_event_get_rawlen(struct slack_event *event)
{
	return event->rawlen;
}

int slack_parse_message(struct slack_callbacks *cb, void *userdata, char *buf, size_t len)
{
	json_t *json;
	json_error_t error;
	const char *type;
	int replyto;
	int res = 0;
	struct slack_event e;

	e.userdata = userdata;
	e.raw = buf;
	e.rawlen = len;

	if (!cb) {
		/* Could happen if slack_send is used before the event loop is started */
		slack_fatal("No callbacks available\n");
		return -1;
	}

	if (!len) {
		slack_error("Received empty message?\n");
		return -1;
	}

	json = json_loads(buf, 0, &error);
	if (!json) {
		slack_error("Failed to load JSON string: %s\n", error.text);
		return -1;
	}

	slack_debug(6, "<== %s\n", buf);

	e.json = json;

	/* Replies don't have a type */
	replyto = json_number_value(json_object_get(json, "reply_to"));
	if (replyto) {
		if (cb->reply) {
			res = cb->reply(&e);
		}
		json_decref(json);
		return res;
	}

	type = json_string_value(json_object_get(json, "type"));
	if (!type) {
		slack_error("Received WebSocket message lacks type: %s\n", buf);
		json_decref(json);
		return -1;
	}

	if (!strcmp(type, "error")) {
		/* This will be fatal to the connection, but not the library */
		slack_error("Slack RTM API error: %s\n", buf);
		json_decref(json);
		return -1;
	/* https://api.slack.com/rtm
	 * https://api.slack.com/events */
	} else if (!strcmp(type, "hello")) {
		
	} else if (!strcmp(type, "accounts_changed")) {
		
	} else if (!strcmp(type, "bot_added")) {
		
	} else if (!strcmp(type, "bot_changed")) {
		
	} else if (!strcmp(type, "channel_archive")) {
		
	} else if (!strcmp(type, "channel_created")) {
		
	} else if (!strcmp(type, "channel_deleted")) {
		
	} else if (!strcmp(type, "channel_history_changed")) {
		
	} else if (!strcmp(type, "channel_joined")) {
		
	} else if (!strcmp(type, "channel_left")) {
		
	} else if (!strcmp(type, "channel_marked")) {
		
	} else if (!strcmp(type, "channel_rename")) {
		
	} else if (!strcmp(type, "channel_unarchive")) {
		
	} else if (!strcmp(type, "commands_changed")) {
		
	} else if (!strcmp(type, "dnd_updated")) {
		
	} else if (!strcmp(type, "dnd_updated_user")) {
		
	} else if (!strcmp(type, "email_domain_changed")) {
		
	} else if (!strcmp(type, "emoji_changed")) {
		
	} else if (!strcmp(type, "external_org_migration_finished")) {
		
	} else if (!strcmp(type, "external_org_migration_started")) {
		
	} else if (!strcmp(type, "file_change")) {
		
	} else if (!strcmp(type, "file_comment_added")) {
		
	} else if (!strcmp(type, "file_comment_deleted")) {
		
	} else if (!strcmp(type, "file_comment_edited")) {
		
	} else if (!strcmp(type, "file_created")) {
		
	} else if (!strcmp(type, "file_deleted")) {
		
	} else if (!strcmp(type, "file_public")) {
		
	} else if (!strcmp(type, "file_shared")) {
		
	} else if (!strcmp(type, "file_unshared")) {
		
	} else if (!strcmp(type, "goodbye")) {
		
	} else if (!strcmp(type, "group_archive")) {
		
	} else if (!strcmp(type, "group_close")) {
		
	} else if (!strcmp(type, "group_deleted")) {
		
	} else if (!strcmp(type, "group_history_changed")) {
		
	} else if (!strcmp(type, "group_joined")) {
		
	} else if (!strcmp(type, "group_left")) {
		
	} else if (!strcmp(type, "group_marked")) {
		
	} else if (!strcmp(type, "group_open")) {
		
	} else if (!strcmp(type, "group_rename")) {
		
	} else if (!strcmp(type, "group_unarchive")) {
		
	} else if (!strcmp(type, "hello")) {
		
	} else if (!strcmp(type, "im_close")) {
		
	} else if (!strcmp(type, "im_created")) {
		
	} else if (!strcmp(type, "im_history_changed")) {
		
	} else if (!strcmp(type, "im_marked")) {
		
	} else if (!strcmp(type, "im_open")) {
		
	} else if (!strcmp(type, "invite_requested")) {
		
	} else if (!strcmp(type, "link_shared")) {
		
	} else if (!strcmp(type, "manual_presence_change")) {
		
	} else if (!strcmp(type, "member_joined_channel")) {
		
	} else if (!strcmp(type, "member_left_channel")) {
		
	} else if (!strcmp(type, "message")) {
		if (cb->message) {
			const char *channel = json_string_value(json_object_get(json, "channel"));
			const char *user = json_string_value(json_object_get(json, "user"));
			const char *text = json_string_value(json_object_get(json, "text"));
			res = cb->message(&e, channel, user, text);
		}
	} else if (!strcmp(type, "pin_added")) {
		
	} else if (!strcmp(type, "pin_removed")) {
		
	} else if (!strcmp(type, "pref_change")) {
		
	} else if (!strcmp(type, "presence_change")) {
		
	} else if (!strcmp(type, "presence_query")) {
		
	} else if (!strcmp(type, "presence_sub")) {
		
	} else if (!strcmp(type, "reaction_added")) {
		
	} else if (!strcmp(type, "reaction_removed")) {
		
	} else if (!strcmp(type, "reconnect_url")) {
		/* Experimental: does nothing? */
	} else if (!strcmp(type, "shared_channel_invite_received")) {
		
	} else if (!strcmp(type, "star_added")) {
		
	} else if (!strcmp(type, "star_removed")) {
		
	} else if (!strcmp(type, "subteam_created")) {
		
	} else if (!strcmp(type, "subteam_members_changed")) {
		
	} else if (!strcmp(type, "subteam_self_added")) {
		
	} else if (!strcmp(type, "subteam_self_removed")) {
		
	} else if (!strcmp(type, "subteam_updated")) {
		
	} else if (!strcmp(type, "team_domain_change")) {
		
	} else if (!strcmp(type, "team_join")) {
		
	} else if (!strcmp(type, "team_migration_started")) {
		
	} else if (!strcmp(type, "team_plan_change")) {
		
	} else if (!strcmp(type, "team_pref_change")) {
		
	} else if (!strcmp(type, "team_profile_change")) {
		
	} else if (!strcmp(type, "team_profile_delete")) {
		
	} else if (!strcmp(type, "team_profile_reorder")) {
		
	} else if (!strcmp(type, "team_rename")) {
		
	} else if (!strcmp(type, "user_change")) {
		
	} else if (!strcmp(type, "user_huddle_changed")) {
		
	} else if (!strcmp(type, "user_profile_changed")) {
		
	} else if (!strcmp(type, "user_status_changed")) {
		
	} else if (!strcmp(type, "user_typing")) {
		if (cb->user_typing) {
			const char *channel = json_string_value(json_object_get(json, "channel"));
			const char *user = json_string_value(json_object_get(json, "user"));
			int id = json_number_value(json_object_get(json, "id"));
			res = cb->user_typing(&e, channel, id, user);
		}
	/* These are all officially undocumented events: */
	} else if (!strcmp(type, "draft_create")) {
	} else if (!strcmp(type, "draft_delete")) {
	} else if (!strcmp(type, "dnd_invalidated")) {
	} else if (!strcmp(type, "user_invalidated")) {
	} else {
		slack_warning("Unhandled event type: %s\n", type);
		slack_debug(1, "Event %s not currently handled: %s\n", type, buf);
		res = -1;
	}

	json_decref(json);
	return res;
}

char *slack_construct_ping(int id)
{
	char *s;
	json_t *json;
	json = json_object();
	if (!json) {
		slack_error("Failed to create JSON object\n");
		return NULL;
	}
	json_object_set_new(json, "id", json_integer(id));
	json_object_set_new(json, "type", json_string("ping"));
	s = json_dumps(json, 0);
	json_decref(json);
	return s;
}

char *slack_channel_construct_message(int id, const char *channel, const char *text)
{
	char *s;
	json_t *json;
	json = json_object();
	if (!json) {
		slack_error("Failed to create JSON object\n");
		return NULL;
	}
	json_object_set_new(json, "id", json_integer(id));
	json_object_set_new(json, "type", json_string("message"));
	json_object_set_new(json, "channel", json_string(channel));
	json_object_set_new(json, "text", json_string(text));
	s = json_dumps(json, 0);
	json_decref(json);
	return s;
}

char *slack_channel_construct_typing(int id, const char *channel)
{
	char *s;
	json_t *json;
	json = json_object();
	if (!json) {
		slack_error("Failed to create JSON object\n");
		return NULL;
	}
	json_object_set_new(json, "id", json_integer(id));
	json_object_set_new(json, "type", json_string("typing"));
	json_object_set_new(json, "channel", json_string(channel));
	s = json_dumps(json, 0);
	json_decref(json);
	return s;
}
