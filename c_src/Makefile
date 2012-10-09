compile: ../priv/bcrypt

../priv/bcrypt:
	$(CC) $(CFLAGS) $(ERL_CFLAGS) $(EXE_LDFLAGS) bcrypt_port.c bcrypt.o blowfish.o $(LDFLAGS) $(ERL_LDFLAGS) -lpthread -o ../priv/bcrypt

clean:
	@rm -f ../priv/bcrypt

.PHONY: clean compile
