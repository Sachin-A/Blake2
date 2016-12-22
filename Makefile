IDIR = include
ODIR = build
CFLAGS = -I $(IDIR) -Wall -lm -g -m32
CC = gcc

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, $(ODIR)/%.o, $(src))
out = blake2s

blake: $(obj)
	$(CC) $(obj) -o $(out) $(CFLAGS)

$(ODIR)/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(ODIR)/*.o *~ core  $(out)
