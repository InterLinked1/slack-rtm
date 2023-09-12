#
# libslackrtm - Client library for Slack RTM
#
# Copyright (C) 2023, Naveen Albert
#
# Naveen Albert <asterisk@phreaknet.org>
#

CC		= gcc
CFLAGS = -Wall -Werror -Wunused -Wextra -Wmaybe-uninitialized -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wnull-dereference -Wformat=2 -Wshadow -Wsizeof-pointer-memaccess -std=gnu99 -pthread -O3 -g -Wstack-protector -fno-omit-frame-pointer -fwrapv -fPIC -D_FORTIFY_SOURCE=2
EXE		= slackrtm
LIBNAME = libslackrtm
RM		= rm -f
INSTALL = install
INSTALL = install

MAIN_SRC := $(wildcard *.c)
MAIN_OBJ = $(MAIN_SRC:.c=.o)

all: library

# NOTE: -lwss, -lssl, and -lcrypto are only needed for the high-level APIs

library: $(MAIN_OBJ)
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(LIBNAME).so $^ -ljansson -lwss -lssl -lcrypto

install: all
	$(INSTALL) -m  755 $(LIBNAME).so "/usr/lib"
	mkdir -p /usr/include/slackrtm
	$(INSTALL) -m 755 *.h "/usr/include/slackrtm/"

examples:
	$(MAKE) --no-builtin-rules -C examples all

uninstall:
	$(RM) /usr/lib/$(LIBNAME).so
	$(RM) /usr/include/slackrtm/*.h
	rm -rf /usr/include/slackrtm

%.o : %.c
	$(CC) $(CFLAGS) -c $^

clean :
	$(RM) *.i *.o *.so $(EXE)

.PHONY: all
.PHONY: install
.PHONY: uninstall
.PHONY: library
.PHONY: examples
.PHONY: clean
