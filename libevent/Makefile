NAME   = echo_server
CC     = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -Werror -g
LDLIBS = -levent
SRC    = echo_server.c

all: $(NAME)

$(NAME): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(NAME)

re: clean all

.PHONY: all clean re
