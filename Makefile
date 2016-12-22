IDIR = include
ODIR = build
BIN = bin
CFLAGS = -I $(IDIR) -Wall -lm -g -std=c89 -Wc90-c99-compat -Wc99-c11-compat -pedantic
CC = gcc

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, $(ODIR)/%.o, $(src))
out = blake2s

blake: $(obj)
	$(CC) $(obj) -o $(BIN)/$(out) $(CFLAGS)

$(ODIR)/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(wildcard $(ODIR)/*.o)  $(wildcard *~) core  $(BIN)/$(out)*
