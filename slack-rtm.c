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
	json_t *json, *okjson;
	json_error_t error;
	const char *type, *subtype;
	int replyto;
	int res = 0;
	struct slack_event event;

	event.userdata = userdata;
	event.raw = buf;
	event.rawlen = len;

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

	slack_debug(8, "<== %s\n", buf);

	event.json = json;

	okjson = json_object_get(json, "ok");
	if (okjson) {
		if (!json_boolean_value(okjson)) {
			slack_warning("Failure: %s\n", buf);
		}
	}

	/* Replies don't have a type */
	replyto = json_number_value(json_object_get(json, "reply_to"));
	if (replyto) {
		if (cb->reply) {
			res = cb->reply(&event);
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
	subtype = json_string_value(json_object_get(json, "subtype")); /* May be NULL */

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
		if (cb->channel_marked) {
			struct slack_event_channel_marked e;
			e.channel = json_string_value(json_object_get(json, "channel"));
			e.ts = json_string_value(json_object_get(json, "ts"));
			e.unread_count = json_number_value(json_object_get(json, "unread_count"));
			e.unread_count_display = json_number_value(json_object_get(json, "unread_count_display"));
			e.num_mentions = json_number_value(json_object_get(json, "num_mentions"));
			e.num_mentions_display = json_number_value(json_object_get(json, "num_mentions_display"));
			e.mention_count = json_number_value(json_object_get(json, "mention_count"));
			e.mention_count_display = json_number_value(json_object_get(json, "mention_count_display"));
			e.event_ts = json_string_value(json_object_get(json, "event_ts"));
			res = cb->channel_marked(&event, &e);
		}
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
		if (subtype) {
			if (!strcmp(subtype, "message_replied")) {
				/* text is NULL with this one */
			} else if (!strcmp(subtype, "message_changed")) {
				if (cb->message_changed) {
					json_t *message = json_object_get(json, "message");
					const char *channel = json_string_value(json_object_get(json, "channel"));
					const char *user = json_string_value(json_object_get(message, "user"));
					const char *text = json_string_value(json_object_get(message, "text"));
					const char *thread_ts = json_string_value(json_object_get(message, "thread_ts")); /* Parent thread ID */
					const char *thread = json_string_value(json_object_get(json, "ts")); /* Thread ID */
					res = cb->message_changed(&event, channel, thread_ts, thread, user, text);
				}
			} else {
				slack_debug(1, "Unhandled message subtype: %s\n", subtype);
			}
		} else if (cb->message) { /* Regular message callback */
			const char *channel = json_string_value(json_object_get(json, "channel"));
			const char *user = json_string_value(json_object_get(json, "user"));
			const char *text = json_string_value(json_object_get(json, "text"));
			const char *thread_ts = json_string_value(json_object_get(json, "thread_ts")); /* Parent thread ID */
			const char *thread = json_string_value(json_object_get(json, "ts")); /* Thread ID */
			/* Other fields:
			 * blocks - rich formatting
			 * client_msg_id
			 * team
			 * source_team
			 * user_team
			 * suppress_notification
			 * event_ts - not really needed: https://api.slack.com/changelog/2016-05-31-more-events-timestamps-in-rtm-api
			 */
			res = cb->message(&event, channel, thread_ts, thread, user, text);
		}
	} else if (!strcmp(type, "pin_added")) {
		
	} else if (!strcmp(type, "pin_removed")) {
		
	} else if (!strcmp(type, "pref_change")) {
		
	} else if (!strcmp(type, "presence_change")) {
		if (cb->presence_change) { /* https://api.slack.com/events/presence_change */
			const char *presence = json_string_value(json_object_get(json, "presence"));
			const char *user = json_string_value(json_object_get(json, "user"));
			json_t *users = json_object_get(json, "users");
			if (users) {
				if (cb->presence_change_multi) { /* Native batched presence callback support */
					res = cb->presence_change_multi(&event, users, presence);
				} else {
					size_t index;
					json_t *value;
					/* Only the single user callback is supported, so user that */
					json_array_foreach(users, index, value) {
						const char *userid = json_string_value(value);
						res |= cb->presence_change(&event, userid, presence);
					}
				}
			} else {
				res = cb->presence_change(&event, user, presence);
			}
		}
	} else if (!strcmp(type, "presence_query")) {
		
	} else if (!strcmp(type, "presence_sub")) {
		
	} else if (!strcmp(type, "reaction_added")) {
		if (cb->reaction_added) {
			const char *user = json_string_value(json_object_get(json, "user"));
			const char *reaction = json_string_value(json_object_get(json, "reaction"));
			const char *channel, *ts;
			/* event_ts, ts not important
			 * The top-level ts is for THIS event, not referring to the ts of the message with which the reaction is associated.
			 * That is in "item": */
			json_t *item = json_object_get(json, "item");
			if (!item) {
				slack_error("reaction_added event contains no item: %s\n", buf);
				res = -1;
				goto cleanup;
			}
			channel = json_string_value(json_object_get(item, "channel"));
			ts = json_string_value(json_object_get(item, "ts"));
			cb->reaction_added(&event, channel, ts, user, reaction);
		}
	} else if (!strcmp(type, "reaction_removed")) {
		
	} else if (!strcmp(type, "reconnect_url")) {
		/* Experimental: does nothing? */
		if (cb->reconnect_url) {
			const char *url = json_string_value(json_object_get(json, "url"));
			res = cb->reconnect_url(&event, url);
		}
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
			const char *thread_ts = json_string_value(json_object_get(json, "thread_ts"));
			const char *user = json_string_value(json_object_get(json, "user"));
			int id = json_number_value(json_object_get(json, "id"));
			res = cb->user_typing(&event, channel, thread_ts, id, user);
		}
	/* These are all officially undocumented events, that can be received via RTM: */
	} else if (!strcmp(type, "apps_changed")) {
	} else if (!strcmp(type, "app_actions_updated")) {
	} else if (!strcmp(type, "apps_installed")) {
	} else if (!strcmp(type, "apps_uninstalled")) {
	} else if (!strcmp(type, "channel_converted_to_shared")) {
	} else if (!strcmp(type, "clear_mention_notification")) {
	} else if (!strcmp(type, "desktop_notification")) {
	} else if (!strcmp(type, "draft_create")) {
	} else if (!strcmp(type, "draft_delete")) {
	} else if (!strcmp(type, "draft_send")) {
	} else if (!strcmp(type, "draft_update")) {
	} else if (!strcmp(type, "dnd_invalidated")) {
	} else if (!strcmp(type, "thread_marked")) {
	} else if (!strcmp(type, "thread_subscribed")) {
	} else if (!strcmp(type, "update_global_thread_state")) {
	} else if (!strcmp(type, "update_thread_state")) {
	} else if (!strcmp(type, "user_interaction_changed")) {
	} else if (!strcmp(type, "user_invalidated")) {
	} else {
		slack_warning("Unhandled event type: %s\n", type);
		slack_debug(1, "Event %s not currently handled: %s\n", type, buf);
		res = -1;
	}

cleanup:
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

char *slack_channel_construct_message(int id, const char *channel, const char *thread_ts, const char *text)
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
	if (thread_ts) {
		json_object_set_new(json, "thread_ts", json_string(thread_ts));
	}
	json_object_set_new(json, "text", json_string(text));
	s = json_dumps(json, 0);
	json_decref(json);
	return s;
}

char *slack_channel_construct_typing(int id, const char *channel, const char *thread_ts)
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
	if (thread_ts) {
		json_object_set_new(json, "thread_ts", json_string(thread_ts));
	}
	s = json_dumps(json, 0);
	json_decref(json);
	return s;
}

static char *slack_users_construct_presence(json_t *userids, const char *type)
{
	char *s;
	json_t *json;
	json = json_object();
	if (!json) {
		slack_error("Failed to create JSON object\n");
		return NULL;
	}
	json_object_set_new(json, "type", json_string(type));
	json_object_set(json, "ids", userids); /* Do not steal the reference, the user passed it in and is responsible for it. */
	s = json_dumps(json, 0);
	json_decref(json);
	return s;
}

char *slack_users_construct_presence_query(json_t *userids)
{
	return slack_users_construct_presence(userids, "presence_query");
}

char *slack_users_construct_presence_subscription(json_t *userids)
{
	return slack_users_construct_presence(userids, "presence_sub");
}
