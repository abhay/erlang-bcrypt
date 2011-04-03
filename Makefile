CC = gcc
CFLAGS = -g -O2 -Wall
ERLANG_LIBS = -lerl_interface -lei -lpthread

BCRYPTLIBS = c_src/bcrypt_port.o c_src/bcrypt.o c_src/blowfish.o

all: compile

compile_port: priv/bcrypt

priv/bcrypt: $(BCRYPTLIBS)
	$(CC) $(CFLAGS) $(BCRYPTLIBS) $(ERLANG_LIBS) -o $@

compile:
	@ ./rebar compile

tests:
	@ ./rebar eunit

clean:
	@ ./rebar clean

