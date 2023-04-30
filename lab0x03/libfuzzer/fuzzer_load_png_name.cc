extern "C" {
#include "pngparser.h"
}
#include <stdio.h>

#include "png_mutator.h"

// LibFuzzer stub
extern "C" int LLVMFuzzerTestOneInput(const char *data, size_t size) {

  struct image *test_img = NULL;
  char name[size + 1];
  strncpy(name, data, size);
  name[size] = '\0';

  // What would happen if we run multiple fuzzing processes at the same time?
  // Take a look at the name of the file.
  if (load_png(name, &test_img) == 0) {
    if (test_img) {
      if (test_img->px)
        free(test_img->px);
      free(test_img);
    }
  }

  // Always return 0
  return 0;
}