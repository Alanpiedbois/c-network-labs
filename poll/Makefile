NAME   = poll_server
CC     = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -Werror -g
SRC    = poll_server.c

all: $(NAME)

$(NAME): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(NAME)

re: clean all

.PHONY: all clean re
