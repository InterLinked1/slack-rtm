# libslackrtm

**C library for the [Slack RTM API](https://api.slack.com/rtm)**

## What is the Slack RTM API?

The Slack RTM API is the low-level Slack API that can be used to build your own Slack client, gateway, or any other program or integration using the Slack API. Unlike modern Slack apps, you can use the RTM API without workspace administrators approving apps, which makes this API more accessible to those looking to tinker with the Slack API.

## Background

At work, we have some Slack channels that people can post to when they have leftover food from meetings. For those who can react quickly enough, it can be a great way to score some free lunch.

While changing notifications from "mentions" to "any message" reduces the chances of missing out, it's still not the most efficient workflow.
During a discussion with a coworker about this, I mused that one shouldn't need to wait for the posts themselves; a good way to one-up everyone else would be to get notifications whenever anyone merely starts *typing* in a free food channel.

Obviously, the official Slack client won't help you here, but it seemed some resourceful use of the Slack API ought to be of use, so I looked into it a little bit.
The officially recommended way nowadays to use the Slack API is to create an "app" and install it in your workspace, but I had the feeling that `$BIG_CORP` would probably not be too enthused about that.

Surprisingly, there are essentially few to no C libraries for interacting with the Slack API in this manner. I generally avoid most of the languages that have ample Slack libraries (e.g. Python, JavaScript, etc.), and these proved to not be very useful to me. A C library was what I wanted, so a C library I wrote. The result is a library for using the Slack RTM API that was sufficiently flexible for my own needs and future growth.

Oh, and if you too want to be the first to get notified about free food, `examples/slack-typing-relay.c` should get you started.

## Authenticating to Slack

There are several different token types that can be used to authenticate to a Slack workspace.

This library uses the `xoxc` (web client) and `xoxd` (web cookie) combination to authenticate to the Slack API. This is essentially a personal user token (much like the old legacy tokens) that provides full access to Slack for a single user.

This can be used to create bots with Slack as well, but note that the bot would be operating as a user (e.g. you) in your workspace, which may not be what you want.

## Getting Tokens

To get the information you'll need to authenticate using this library, you'll need to do the following in your web browser:

- Log in to the Slack workspace you want to use in your browser

- Open the F12 browser developer console

- Under "Application", select "Cookies" and look for the `d` cookie. The value will start with `xoxd-`. Copy the URL-encoded value of this cookie. Chromium browsers (e.g. Chrome) will display this URL-encoded, but Firefox-based browsers may show it already decoded, in which case you'll need to manually re-encode it.

- Under "Network", select `WS` to filter your network connections to WebSocket connections. Click on the WebSocket connection that begins with `?token` and select "Headers" to view the request headers for the connection. You'll see something that looks like this:

`wss://wss-primary.slack.com/?token=xoxc-MYTOKEN&sync_desync=1&slack_client=desktop&start_args=URLENCODEDARGUMENTS&no_query_on_subscribe=1&flannel=3&lazy_channels=1&gateway_server=GWSERVER&batch_presence_aware=1`

- Extract your token, beginning with (and including) `xoxc-` from `MYTOKEN` and extract your gateway server from `GWSERVER`

**Enterprise Workspaces**

If you are connecting to an enterprise workspace, there are a couple extra things you'll need:

- From the WebSocket connection URL, you'll need the Enterprise ID (`enterprise_id` query parameter)

- You'll probably also need to provide the `d-s` cookie, not just the `d` cookie

It should go without saying, but **you must keep this information safe**! Your token and cookie(s) will give anyone with access to them unfettered access to your Slack workspace *as you*. Treat these just like you would your username and password.

## Library Overview

This library is split into both a "low level" API and a "high level" API as follows:

- `<libslackrtm/slack.h>` - General header file. Always include this.

- `<libslackrtm/slack-rtm.h>` - Low-level library functions. This is for interacting with the Slack RTM API directly. If you want to handle the WebSocket connection yourself, then you might want to use this directly. You will be responsible for all network I/O.

- `<libslackrtm/slack-client.h>` - High-level library functions. This includes TLS support, WebSocket connectivity, and wrappers around RTM APIs. If you just want to do high-level things like "post a message", "do this when that happens", etc. then you'll probably want to use this instead of the low-level library functions directly. The library will handle the WebSocket client connection, TLS encryption, network I/O, etc. all for you.

## Building and Installing

`libslackrtm` is primarily tested on Debian distros, but should be portable to most Linux platforms, and possibly Unix platforms as well.

`libslackrtm` has the following dependencies, so make sure you have them:

- `libjansson` - JSON library. You can usually install this using your package manager (e.g. `apt-get install libjansson-dev`)

- `libssl` and `libcrypto` - OpenSSL support, used by the high-level APIs. You probably already have these, but if not, install your distro's OpenSSL package.

- `libwss` - WebSocket library, used by the high-level APIs. You'll need to compile this from source and install the shared library, following the instructions here: https://github.com/InterLinked1/libwss

Compiling `libslackrtm` itself is very easy:

- Run `make` to compile the library

- Run `make install` to install the shared library on your system (which can then be linked to using `-lslackrtm`)

- Run `make examples` to compile example programs, used to demonstrate library usage. These will produce standalone binaries in the `examples` directory that you can run.

If you're doing all of this at once on a Debian system, you can run something along these lines:

```
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install make gcc libssl-dev libjansson-dev
git clone https://github.com/InterLinked1/libwss.git
cd libwss/
make
sudo make install
cd ..
git clone https://github.com/InterLinked1/slack-rtm.git
cd slack-rtm
make
sudo make install
make examples
```

## Running the Example Programs

This repository comes with some example programs that demonstrate library usage and functionality. They all require the following arguments on the command line:

- `-c [cookie]` - Your cookie

- `-s [gwserver]` - Gateway server ID

- `-t [token]` - Your token

These settings can also be set using environment variables, if that is more convenient for you.

Some example programs may require additional arguments; consult the program help for full usage.

**WARNING:** Some of the example programs may be highly disruptive to busy workspaces. The example programs are meant to merely demonstrate usage and are not production-ready.
Any testing should be done in a sandbox workspace. Otherwise, you may attract the wrath of your coworkers.

This library itself is licensed under the GNU Lesser General Public License, but the example program code is all licensed under the Apache license, so feel free to use that as a starting point in your own programs.

## Known Issues

Posting messages to an enterprise workspace may fail when using the RTM API. This is a known defect with the RTM API itself, not this library, and one which Slack does not care to address, since the RTM API is deprecated and use of xoxc/xoxd tokens are not officially supported.

As a workaround, you could use the [`chat.postMessage`](https://api.slack.com/methods/chat.postMessage) API, which is what the official Slack client uses. Since that is not using the RTM API, that is out-of-scope for this library.

Non-enterprise workspaces are not affected and you should be able to post to them using the RTM API.

## Contributions, Issues, Bugs, etc.

This library is still incomplete in the sense that not all events have callback functions and not all commands have functions yet. The most common types of things are implemented, but some of the lesser used stuff is not. Contributions to add missing functionality are welcome. Otherwise, if functionality you require is not currently available, feel free to open an issue.
