CC = clang
override CFLAGS += -g -w -O3 -fsanitize=fuzzer,address

all: libpngparser fuzzer_load_png fuzzer_load_png_name fuzzer_store_png_rgba fuzzer_store_png_palette fuzzer_load_png_custom_mutator fuzzer_store_png_rgba_custom_mutator fuzzer_store_png_palette_custom_mutator

clean:
	rm -f libpngparser.a fuzzer_load_png fuzzer_load_png_name fuzzer_store_png_rgba fuzzer_store_png_palette fuzzer_load_png_custom_mutator fuzzer_store_png_rgba_custom_mutator fuzzer_store_png_palette_custom_mutator *.o

.PHONY: all clean

libpngparser: pngparser.h pngparser.c crc.c crc.h
	$(CC) $(CFLAGS) -c pngparser.c crc.c
	ar rcs libpngparser.a pngparser.o crc.o

fuzzer_load_png: libpngparser
	$(CC) $(CFLAGS) -o fuzzer_load_png fuzzer_load_png.cc libpngparser.a -lz
# Include "png_mutator.h" in fuzzer_load_png.cc and append -DPNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR to enable the example PNG mutator

# TODO: fuzzer_load_png_name:
# Fuzzes the filename argument of load_png.
fuzzer_load_png_name: fuzzer_load_png_name.cc libpngparser
	$(CC) $(CFLAGS) -o $@ $< libpngparser.a -lz -DPNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR

# TODO: fuzzer_store_png_rgba:
# Fuzzes store_png RGBA file interface (no palette).
fuzzer_store_png_rgba: fuzzer_store_png_rgba.cc libpngparser
	$(CC) $(CFLAGS) -o $@ $< libpngparser.a -lz -DPNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR

# TODO: fuzzer_store_png_palette:
# Fuzzes store_png palette file interface (fixed palette).
fuzzer_store_png_palette: fuzzer_store_png_palette.cc libpngparser
	$(CC) $(CFLAGS) -o $@ $< libpngparser.a -lz -DPNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR

# TODO: fuzzer_load_png_custom_mutator:
# Include your custom mutator yolo_png_mutator.h in fuzzer_load_png.cc and append -DYOLO_PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR.
fuzzer_load_png_custom_mutator: fuzzer_load_png.cc libpngparser yolo_png_mutator.h
	$(CC) $(CFLAGS) -o $@ $< libpngparser.a -lz -DYOLO_PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR


# TODO: fuzzer_store_png_rgba_custom_mutator: 
# Fuzzes store_png RGBA file interface (no palette) with your custom mutator. 
# Include your yolo_png_mutator.h in fuzzer_store_png_rgba.cc and append -DYOLO_PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR to enable it.
fuzzer_store_png_rgba_custom_mutator: fuzzer_store_png_rgba.cc libpngparser yolo_png_mutator.h
	$(CC) $(CFLAGS) -o $@ $< libpngparser.a -lz -DYOLO_PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR

# TODO: fuzzer_store_png_palette_custom_mutator: 
# Fuzzes store_png palette file interface (fixed palette) with your custom mutator. 
# Include your yolo_png_mutator.h in fuzzer_store_png_palette.cc and append -DYOLO_PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR to enable it.
fuzzer_store_png_palette_custom_mutator: fuzzer_store_png_palette.cc libpngparser yolo_png_mutator.h
	$(CC) $(CFLAGS) -o $@ $< libpngparser.a -lz -DYOLO_PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR

# Enable this after you finish the TODOs, run `make check` to see if you fix the example bug correctly and your code compiles successfully
check: libpngparser fuzzer_load_png fuzzer_load_png_name fuzzer_store_png_rgba fuzzer_store_png_palette fuzzer_load_png_custom_mutator fuzzer_store_png_rgba_custom_mutator fuzzer_store_png_rgba_custom_mutator
	./fuzzer_load_png example_crash

size: libpngparser size.c
	clang -g -w -O3 -fsanitize=address -o size size.c libpngparser.a -lz