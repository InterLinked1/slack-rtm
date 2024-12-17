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
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*!
 * \brief Parse a raw JSON payload and dispatch the appropriate callback
 * \param cb Callbacks structure
 * \param slack Slack client passed to callbacks
 * \param userdata Custom user data passed to callbacks
 * \param buf Raw WebSocket text message
 * \param len Length of WebSocket message
 * \retval -1 if the event was not parsed successfully
 * \return Return value from user callback function
 */
int slack_parse_message(struct slack_callbacks *cb, void *userdata, char *buf, size_t len);

/*!
 * \brief Construct a ping message
 * \param id Unique ID for operation on this connection
 * \return JSON payload to send on WebSocket on success
 * \return NULL on failure
 */
char *slack_construct_ping(int id);

/*!
 * \brief Construct a message to send to a channel
 * \param id Unique ID for operation on this connection
 * \param channel Channel ID (not name)
 * \param thread_ts Parent thread ID (NULL if none)
 * \param text
 * \warning As of August 29, 2024, this may no longer work in enterprise workspaces and Slack does not care to address this issue.
 *       Should continue to work normally in non-enterprise workspaces.
 * \return JSON payload to send on WebSocket on success
 * \return NULL on failure
 */
char *slack_channel_construct_message(int id, const char *channel, const char *thread_ts, const char *text);

/*!
 * \brief Construct a typing indicator to send to a channel
 * \param id Unique ID for operation on this connection
 * \param channel Channel ID (not name)
 * \param thread_ts Parent thread ID (NULL if none)
 * \return JSON payload to send on WebSocket on success
 * \return NULL on failure
*/
char *slack_channel_construct_typing(int id, const char *channel, const char *thread_ts);

/*!
 * \brief Construct a presence query
 * \param userids A jansson json array containing user IDs, up to a maximum of 500 user IDs.
 * \return JSON payload to send on WebSocket on success
 * \return NULL on failure
 */
char *slack_users_construct_presence_query(json_t *userids);

/*!
 * \brief Construct a presence subscription, to subscribe to future presence changes.
 * \param userids A jansson json array containing user IDs. Slack recommends capping this at 500 user IDs.
 * \return JSON payload to send on WebSocket on success
 * \return NULL on failure
 */
char *slack_users_construct_presence_subscription(json_t *userids);
