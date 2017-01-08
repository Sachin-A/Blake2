IDIR = include
ODIR = build
BIN = bin
CFLAGS = -I $(IDIR) -Wall -lm -g -Wc99-c11-compat -pedantic
CC = gcc

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, $(ODIR)/%.o, $(src))
out = blake2b

blake: $(obj) | bin
	$(CC) $(obj) -o $(BIN)/$(out) $(CFLAGS)

$(ODIR)/%.o: src/%.c | build
	$(CC) -c $< -o $@ $(CFLAGS)

bin:
	mkdir $(BIN)

build:
	mkdir $(ODIR)

clean:
	rm -f $(wildcard $(ODIR)/*.o) $(wildcard *~) core  $(BIN)/$(out)*
