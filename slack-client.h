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
 * \brief Client library for Slack RTM (Real Time Messaging) - high-level APIs
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*! \brief Structure for a single Slack RTM connection */
struct slack_client;

/*!
 * \brief Create a Slack client
 * \param userdata Custom user data that will be provided in callback functions
 * \note Must be cleaned up using slack_session_destroy
 */
struct slack_client *slack_client_new(void *userdata);

/*! \brief Clean up and free a Slack client created using slack_client_new */
void slack_client_destroy(struct slack_client *slack);

/*!
 * \brief Establish a Slack RTM client connection
 * \param slack
 * \param gwserver Gateway server ID
 * \param token Slack token (for web tokens, begins with xoxc-)
 * \param cookie The 'd' cookie (begins with xoxd). This is required for xoxc tokens. Otherwise, set to NULL.
 * \retval 0 on success, -1 on failure
 */
int slack_client_connect(struct slack_client *slack, const char *gwserver, const char *token, const char *cookie);

/*!
 * \brief Run the event loop for a Slack client
 * \param slack
 * \param cb Callbacks to execute on events
 * \note This is blocking. Use slack_client_interrupt from another thread to cause slack_event_loop to exit.
 */
void slack_event_loop(struct slack_client *slack, struct slack_callbacks *cb);

/*! \brief Interrupt and terminate a Slack client's event loop */
void slack_client_interrupt(struct slack_client *slack);

/*!
 * \brief Post a message to a channel.
 * \param slack
 * \param channel Channel ID (not name)
 * \param text Message text. Should be under 4,000 characters and must be no greater than 16 KB.
 * \retval 0 on success, -1 on failure
 */
int slack_channel_post_message(struct slack_client *slack, const char *channel, const char *text);

/*!
 * \brief Indicate typing to a channel.
 * \param slack
 * \param channel Channel ID (not name)
 * \retval 0 on success, -1 on failure
 */
int slack_channel_indicate_typing(struct slack_client *slack, const char *channel);

/*
 * \brief Whether a string represents a valid Slack channel ID
 * \note All channel IDs starts with a C, D, or G: https://api.slack.com/docs/conversations-api#shared_channels
 * \retval 1 if valid, 0 if invalid
 */
#define slack_valid_channel_id(s) (s && *s && (*s == 'C' || *s == 'D' || *s == 'G'))
