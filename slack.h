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
 * \brief Client library for Slack RTM (Real Time Messaging)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define SLACK_RTM_LIB_VERSION_MAJOR 0
#define SLACK_RTM_LIB_VERSION_MINOR 3
#define SLACK_RTM_LIB_VERSION_PATCH 4

#define SLACK_LOG_NONE 0
#define SLACK_LOG_FATAL 1
#define SLACK_LOG_ERROR 2
#define SLACK_LOG_WARNING 3
#define SLACK_LOG_NOTICE 4
#define SLACK_LOG_DEBUG 5

/*! \brief Set a logging callback */
void slack_set_logger(void (*logger)(int level, int bytes, const char *file, const char *function, int line, const char *msg));

/*!
 * \brief Set the maximum log level to log
 * \param level Maximum log level. For non-debug level, use the log level name. For a debug level, use SLACK_LOG_DEBUG + the max debug level.
 */
void slack_set_log_level(int level);

/*! \note
 * This library consists of both higher level and lower level functions.
 * They are mostly mutually exclusive in the sense that you should
 * only need to use one or the other (but it's perfectly fine to use both, too).
 * Use the high-level APIs in slack-client.h for a higher level interface,
 * and use the low-level APIs in slack-rtm.h directly if you are managing the WebSocket connection yourself.
 */

/* Opaque event */
struct slack_event;

/*! \brief Get the user data associated with a Slack client */
void *slack_event_get_userdata(struct slack_event *event);

#ifdef SLACK_EXPOSE_JSON
/*!
 * \brief Get the parsed JSON object for an event
 * \note The returned object is only valid until the callback returns
 * \note You must define SLACK_EXPOSE_JSON (and include <jansson.h> in your source file before including slack.h to use this function
 */
const json_t *slack_event_get_json(struct slack_event *event);
#endif

/*! \brief Get the raw message of an event */
const char *slack_event_get_raw(struct slack_event *event);

/*! \brief Get the length of the raw message of an event */
size_t slack_event_get_rawlen(struct slack_event *event);

struct slack_event_channel_marked {
	const char *channel;
	const char *ts;				/*!< Thread */
	int unread_count;
	int unread_count_display;
	int num_mentions;
	int num_mentions_display;
	int mention_count;
	int mention_count_display;
	const char *event_ts;
};

/*! \brief User callbacks for received events */
struct slack_callbacks {
	/* Command reply callback */
	int (*reply)(struct slack_event *event);	/*! \note This callback is automatically set up by the high level API */
	/* Callback for all events. This callback, if provided, will be triggered for all events,
	 * regardless if they are handled by other callbacks or not.
	 * If this returns 0, event-specific callbacks will not be invoked.
	 */
	int (*all)(struct slack_event *event);
	/* Event callbacks */
	int (*channel_marked)(struct slack_event *event, struct slack_event_channel_marked *channel_marked);
	int (*message)(struct slack_event *event, const char *channel, const char *thread_ts, const char *ts, const char *user, const char *text);
	int (*message_changed)(struct slack_event *event, const char *channel, const char *thread_ts, const char *ts, const char *user, const char *text);
	int (*presence_change)(struct slack_event *event, const char *user, const char *presence);
#ifdef SLACK_EXPOSE_JSON
	int (*presence_change_multi)(struct slack_event *event, json_t *userids, const char *presence);
#else
	/* Define a dummy callback if json_t type is not exposed to an application.
	 * This ensures proper offsets for the struct; otherwise files without SLACK_EXPOSE_JSON
	 * will use the wrong offset into the struct for any following callbacks.
	 * This is fine, because in this case, this callback isn't being used. */
	int (*presence_change_multi)(void);
#endif
	int (*reaction_added)(struct slack_event *event, const char *channel, const char *ts, const char *user, const char *reaction);
	int (*reconnect_url)(struct slack_event *event, const char *url);
	int (*user_typing)(struct slack_event *event, const char *channel, const char *thread_ts, int id, const char *user);
};
