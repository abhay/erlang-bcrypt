ERL_TOP=../otp
include $(ERL_TOP)/make/target.mk

INCLUDES = \
  -I$(ERL_TOP)/erts/$(TARGET) \
  -I$(ERL_TOP)/erts/emulator/$(TARGET) \
  -I$(ERL_TOP)/erts/emulator/$(TARGET)/opt/smp \
  -I$(ERL_TOP)/erts/emulator/beam/ \
  -I$(ERL_TOP)/erts/emulator/sys/unix \
  -I$(ERL_TOP)/erts/include/$(TARGET) \
  -I$(ERL_TOP)/erts/include/internal \
  -no-cpp-precomp  -DHAVE_CONFIG_H

# OS X Snow Leopard flags.
GCCFLAGS = -m64 -O3 -fPIC -bundle -flat_namespace -undefined suppress -fno-common -Wall

# Linux Flags
#GCCFLAGS = -O3 -fPIC -shared -fno-common -Wall

CFLAGS = $(GCCFLAGS) $(INCLUDES)
LDFLAGS = $(GCCFLAGS) $(LIBS)

OBJECTS = lib/bcrypt/c_src/blowfish.o lib/bcrypt/c_src/bcrypt.o lib/bcrypt/c_src/bcrypt_nif.o

DRIVER = lib/bcrypt/c_src/bcrypt_nif.so
BEAM = lib/bcrypt/ebin/bcrypt_nif.beam

all: $(DRIVER) $(BEAM)

clean:
	rm -f *.o *.beam $(DRIVER)

$(DRIVER): $(OBJECTS)
	gcc -o $@ $^ $(LDFLAGS)

$(BEAM): lib/bcrypt/src/bcrypt_nif.erl
	erlc $^