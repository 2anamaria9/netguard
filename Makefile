CC = gcc
CFLAGS = -Wall -Wextra -g -Iengine/include
LDFLAGS = -lpcap
SRC = $(wildcard engine/src/*.c)
OBJ = $(SRC:.c=.o)

netguard: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

asan: CFLAGS += -fsanitize=address
asan: LDFLAGS += -fsanitize=address
asan: clean netguard

clean:
	rm -f engine/src/*.o netguard

.PHONY: clean asan
