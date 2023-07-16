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
 * \brief Set root CA certificates used for TLS
 * \param rootcerts Full path to file containing root CA certificates
 */
void slack_set_tls_root_certs(const char *rootcerts);

/*!
 * \brief Create a Slack client
 * \param userdata Custom user data that will be provided in callback functions
 * \note Must be cleaned up using slack_session_destroy
 */
struct slack_client *slack_client_new(void *userdata);

/*! \brief Get the userdata provided in slack_client_new */
void *slack_client_get_userdata(struct slack_client *client);

/*! \brief Clean up and free a Slack client created using slack_client_new */
void slack_client_destroy(struct slack_client *slack);

/*!
 * \brief Set the entire connection request URI (without hostname) for the WebSocket connection.
 *        This will include the token, gateway server, enterprise ID, etc. in the URI.
 * \param[in] url Entire request URI. This reference must remain valid until slack_client_connect is called.
 * \note You should use slack_client_set_token, slack_client_set_gateway_server, and slack_client_set_enterprise_id
 *       separately instead if possible. This is a lower-level function that should only be used as a last resort.
 */
void slack_client_set_connect_url(struct slack_client *slack, const char *url);

/*!
 * \brief Set the Slack token for connection (for web tokens, begins with xoxc-)
 * \param[in] token Slack token. This reference must remain valid until slack_client_connect is called.
 */
void slack_client_set_token(struct slack_client *slack, const char *token);

/*!
 * \brief Set the gateway server for connection
 * \param[in] gwserver Gateway server ID. This reference must remain valid until slack_client_connect is called.
 */
void slack_client_set_gateway_server(struct slack_client *slack, const char *gwserver);

/*!
 * \brief Set the enterprise ID of the client
 * \param[in] entid Enterprise ID. This reference must remain valid until slack_client_connect is called.
 * \note If you are not connecting to an enterprise workspace, you do not need to call this function.
 */
void slack_client_set_enterprise_id(struct slack_client *slack, const char *entid);

/*!
 * \brief Set the cookies header for the connection
 * \param[in] The raw value of the Cookie header to send. This reference must remain valid until slack_client_connect is called.
 * \note If possible, use slack_client_set_cookie instead; only use this as a last resort.
 */
void slack_client_set_cookies(struct slack_client *slack, const char *cookies);

/*!
 * \brief Set a required cookie for the connection
 * \param[in] name Cookie name. The 'd' cookie is required and 'd-s' may also be required (e.g. for enterprises)
 *                 Other cookies are ignored by this function.
 * \param[in] value Cookie value. This reference must remain valid until slack_client_connect is called.
 */
void slack_client_set_cookie(struct slack_client *slack, const char *name, const char *value);

/*!
 * \brief Check if it is possible to connect to the Slack RTM API
 * \param[in[ slack
 * \retval 1 Sufficient parameters to connect to Slack API
 * \retval 0 Some or all connection information is missing or invalid (use the slack_client_set_ functions to remedy this)
 */
int slack_client_connect_possible(struct slack_client *slack);

/*!
 * \brief Establish a Slack RTM client connection
 * \param slack
 * \param gwserver Gateway server ID
 * \param token Slack token (for web tokens, begins with xoxc-)
 * \param cookie The 'd' cookie (begins with xoxd). This is required for xoxc tokens. Otherwise, set to NULL.
 * \retval 0 on success, -1 on failure
 */
int slack_client_connect(struct slack_client *slack);

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
