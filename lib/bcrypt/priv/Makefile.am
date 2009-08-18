## Copyright (c) 2009 Hunter Morris <huntermorris@gmail.com>

## Permission to use, copy, modify, and distribute this software for any
## purpose with or without fee is hereby granted, provided that the above
## copyright notice and this permission notice appear in all copies.

## THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
## WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
## MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
## ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
## WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
## ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
## OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

bcryptprivlibdir = $(localerlanglibdir)/bcrypt/priv

bcryptprivlib_PROGRAMS = bcrypt

bcrypt_SOURCES = \
	../c_src/bcrypt_erlang.c \
	../c_src/blowfish.c \
	../c_src/bcrypt.c \
	../c_src/erl_blf.h

bcrypt_LDADD = -lpthread -lerl_interface -lei
