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
#define SLACK_RTM_LIB_VERSION_MINOR 2
#define SLACK_RTM_LIB_VERSION_PATCH 0

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

/* Only used by the high-level API */
struct slack_client;

/*! \brief User callbacks for received events */
struct slack_callbacks {
	int (*reply)(struct slack_client *client, void *userdata, const char *data, size_t len);	/*! \note This callback is automatically set up by the high level API */
	int (*user_typing)(struct slack_client *client, void *userdata, const char *channel, int id, const char *user);
};

/*! \note
 * This library consists of both higher level and lower level functions.
 * They are mostly mutually exclusive in the sense that you should
 * only need to use one or the other (but it's perfectly fine to use both, too).
 * Use the high-level APIs in slack-client.h for a higher level interface,
 * and use the low-level APIs in slack-rtm.h directly if you are managing the WebSocket connection yourself.
 */
