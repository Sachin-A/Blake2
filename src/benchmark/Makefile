IDIR = ../../include
CC=gcc
CFLAGS=-O3 -march=native -Wall -lm -g -std=c89 -Wc90-c99-compat -Wc99-c11-compat -pedantic -DBENCHMARK -I $(IDIR)
FILES=benchmark.c

all: bench

bench: benchmark.c
	$(CC) $(FILES) $(CFLAGS) ../blake2b.c -o blake2b
	$(CC) $(FILES) $(CFLAGS) md5.c -o md5  -lcrypto -lz

plot: bench
	./blake2b > blake2b.data
	./md5 > md5.data
	gnuplot plot.gplot

clean:
	rm -f blake2b md5 benchmark.pdf blake2b.data md5.data
