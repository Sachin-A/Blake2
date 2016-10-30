IDIR = include
CFLAGS = -I $(IDIR) -Wall
CC = gcc

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, build/%.o, $(src))
out = blake2b

blake: $(obj)
	$(CC) $(obj) -o $(out)

build/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f build/*.o *~ core  $(out)
