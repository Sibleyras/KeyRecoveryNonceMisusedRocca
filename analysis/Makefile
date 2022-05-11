SRC := $(wildcard ../src/*.c)
CFLAGS := -I../include -O2 -Wall
CC := gcc
.PHONY: keyrecovery
test: $(SRC) keyrecovery.c
	$(CC) $(CFLAGS) $^ -o rocca.keyrecovery && ./rocca.keyrecovery
