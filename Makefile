IDIR = include
ODIR = build
CFLAGS = -I $(IDIR) -Wall -lm -g -std=c89 -Wc90-c99-compat -Wc99-c11-compat
CC = gcc

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, $(ODIR)/%.o, $(src))
out = blake2b

blake: $(obj)
	$(CC) $(obj) -o $(out) $(CFLAGS)

$(ODIR)/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(wildcard $(ODIR)/*.o) $(wildcard *~) core  $(out).exe
