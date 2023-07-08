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
 * \brief Internal logging
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define slack_fatal(fmt, ...) slack_log(SLACK_LOG_FATAL, __FILE__, __func__, __LINE__, fmt, ## __VA_ARGS__)
#define slack_error(fmt, ...) slack_log(SLACK_LOG_ERROR, __FILE__, __func__, __LINE__, fmt, ## __VA_ARGS__)
#define slack_warning(fmt, ...) slack_log(SLACK_LOG_WARNING, __FILE__, __func__, __LINE__, fmt, ## __VA_ARGS__)
#define slack_notice(fmt, ...) slack_log(SLACK_LOG_NOTICE, __FILE__, __func__, __LINE__, fmt, ## __VA_ARGS__)
#define slack_debug(level, fmt, ...) slack_log(SLACK_LOG_DEBUG + level, __FILE__, __func__, __LINE__, fmt, ## __VA_ARGS__)

void __attribute__ ((format (printf, 5, 6))) slack_log(int level, const char *file, const char *function, int line, const char *fmt, ...);
