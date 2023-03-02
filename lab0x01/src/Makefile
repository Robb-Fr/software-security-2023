CC = gcc
override CFLAGS += -g -w -O3

all: libpngparser solid checkerboard filter circle epfl rect resize tests

clean:
	rm -f libpngparser.a tests solid checkerboard filter circle epfl rect resize *.o

.PHONY: all clean fix_all_bugs tests

libpngparser: pngparser.h pngparser.c crc.c crc.h
	$(CC) $(CFLAGS) -c pngparser.c crc.c
	ar rcs libpngparser.a pngparser.o crc.o


solid: libpngparser solid.c
	$(CC) $(CFLAGS) -o solid solid.c libpngparser.a -lz

checkerboard: libpngparser checkerboard.c
	$(CC) $(CFLAGS) -o checkerboard checkerboard.c libpngparser.a -lz

filter: libpngparser filter.c
	$(CC) $(CFLAGS) -o filter filter.c libpngparser.a -lz -lm

circle: libpngparser circle.c
	$(CC) $(CFLAGS) -o circle circle.c libpngparser.a -lz -lm

epfl: libpngparser epfl.c
	$(CC) $(CFLAGS) -o epfl epfl.c libpngparser.a -lz -lm

rect: libpngparser rect.c
	$(CC) $(CFLAGS) -o rect rect.c libpngparser.a -lz

resize: libpngparser resize.c
	$(CC) $(CFLAGS) -o resize resize.c libpngparser.a -lm -lz

tests: tests.o filter.o libpngparser.a
	$(CC) $(CFLAGS) -Werror -Wall tests.o filter.o libpngparser.a -lcheck -lm -lz -lrt -lpthread -lsubunit -o tests

tests.o: tests.c filter.h
