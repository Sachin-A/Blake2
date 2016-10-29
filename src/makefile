IDIR =../include
CC= gcc
CFLAGS= -I$(IDIR)

ODIR =obj
LDIR =../lib

LIBS=-lm

_DEPS= blake2b.h
DEPS= $(patsubst %, $(IDIR)/%, $(_DEPS))

_OBJ= blake2b.o blake2b_functions.o
OBJ= $(patsubst %, $(ODIR)/%, $(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

blake2b:  $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
