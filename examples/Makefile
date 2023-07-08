#
# libslackrtm - example programs
#
# Copyright (C) 2023, Naveen Albert
#
# Naveen Albert <asterisk@phreaknet.org>
#

CC		= gcc
CFLAGS = -Wall -Werror -Wno-unused-parameter -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wformat=2 -Wshadow -std=gnu99 -pthread -O0 -g -Wstack-protector -fno-omit-frame-pointer -D_FORTIFY_SOURCE=2
LIBS	= -lslackrtm
RM		= rm -f

SRCS := $(wildcard slack-*.c)
OBJS = $(SRCS:.c=.o)
EXES = $(patsubst %.o,%,$(OBJS))

all : example-common.o $(EXES)

# XXX: This is not quite right, as it recreates all binaries whenever an object file needs to be recreated.
# What we really want to do is have each EXE depend on its corresponding OBJ file (with .o extension)
$(EXES): $(OBJS) example-common.o
	$(CC) $(CFLAGS) -o $@ example-common.o $@.o $(LIBS)

%.o : %.c
	$(CC) $(CFLAGS) -c $^

clean :
	$(RM) *.i *.o

.PHONY: all
.PHONY: clean
