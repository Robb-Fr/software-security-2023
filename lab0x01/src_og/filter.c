#include "pngparser.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

#define ARG_SIZE 255

/* This filter iterates over the image and calculates the average value of the
 * color channels for every pixel This value is then written to all the channels
 * to get the grayscale representation of the image
 */
void filter_grayscale(struct image *img, void *weight_arr) {
  struct pixel(*image_data)[img->size_x] =
      (struct pixel(*)[img->size_x])img->px;
  double *weights = (double *)weight_arr;

  /* BUG!
   * This bug isn't graded.
   *
   * FIX: Initialize both variables to 0.
   */
  for (unsigned short i; i < img->size_y; i++) {
    for (unsigned short j; j < img->size_x; j++) {
      double luminosity = 0;

      luminosity += weights[0] * image_data[i][j].red;
      luminosity += weights[1] * image_data[i][j].green;
      luminosity += weights[2] * image_data[i][j].blue;

      image_data[i][j].red = (uint8_t)luminosity;
      image_data[i][j].green = (uint8_t)luminosity;
      image_data[i][j].blue = (uint8_t)luminosity;
    }
  }
}

/* This filter blurs an image. The larger the radius, the more noticeable the
 * blur.
 *
 * For every pixel we define a square of side 2*radius+1 centered around it.
 * The new value of the pixel is the average value of all pixels in the square.
 *
 * Pixels of the square which fall outside the image do not count towards the
 * average. They are ignored (e.g. 5x5 box will turn into a 3x3 box in the
 * corner).
 *
 */
void filter_blur(struct image *img, void *r) {
  struct pixel(*image_data)[img->size_x] =
      (struct pixel(*)[img->size_x])img->px;
  int radius = *((int *)r);
  if (radius < 0) {
    radius = 0;
  }

  struct pixel(*new_data)[img->size_x] =
      malloc(sizeof(struct pixel) * img->size_x * img->size_y);

  if (!new_data) {
    return;
  }

  /* We iterate over all pixels */
  for (long i = 0; i <= img->size_y; i++) {
    for (long j = 0; j <= img->size_x; j++) {

      unsigned long long red = 0, green = 0, blue = 0, alpha = 0;
      /* We iterate over all pixels in the square */
      for (long y_offset = -radius; y_offset <= radius; y_offset++) {
        for (long x_offset = -radius; x_offset <= radius; x_offset++) {

          /* BUG!
           * This bug isn't graded.
           *
           * FIX: Limit reads only to valid memory
           */
          struct pixel current = image_data[i + y_offset][j + x_offset];

          red += current.red;
          blue += current.blue;
          green += current.green;
          alpha += current.alpha;
        }
      }

      int num_pixels = (2 * radius + 1) * (2 * radius + 1);
      /* Calculate the average */
      red /= num_pixels;
      green /= num_pixels;
      blue /= num_pixels;
      alpha /= num_pixels;

      /* Assign new values */
      new_data[i][j].red = red;
      new_data[i][j].green = green;
      new_data[i][j].blue = blue;
      new_data[i][j].alpha = alpha;
    }
  }

  free(img->px);
  img->px = (struct pixel *)new_data;
  return;
}

/* We allocate and return a pixel */
struct pixel *get_pixel() {
  struct pixel px;
  return &px;
}

/* This filter just negates every color in the image */
void filter_negative(struct image *img, void *noarg) {
  struct pixel(*image_data)[img->size_x] =
      (struct pixel(*)[img->size_x])img->px;

  /* Iterate over all the pixels */
  for (long i = 0; i <= img->size_y; i++) {
    for (long j = 0; j <= img->size_x; j++) {

      struct pixel current = image_data[i][j];
      struct pixel *neg = get_pixel();

      /* The negative is just the maximum minus the current value */
      neg->red = 255 - current.red;
      neg->green = 255 - current.green;
      neg->blue = 255 - current.blue;
      neg->alpha = current.alpha;

      /* Write it back */
      image_data[i][j] = *neg;
    }
  }
}

/* Set the transparency of the picture to the value (0-255) passed as argument
 */
void filter_specific_color(struct image *img, void *specific_color) {
  struct pixel(*image_data)[img->size_x] =
      (struct pixel(*)[img->size_x])img->px;
  long hex_color = *((long *)specific_color);

  /* Iterate over all pixels */
  for (long i = 0; i < img->size_y; i++) {
    for (long j = 0; j < img->size_x; j++) {
      if (image_data[i][j].red != (hex_color & 0xff0000) >> 16 ||
          image_data[i][j].green != (hex_color & 0x00ff00) >> 8 ||
          image_data[i][j].blue != (hex_color & 0x0000ff)) {
        image_data[i][j].alpha = 0;
      }
    }
  }
}

/* This filter is used to detect edges by computing the gradient for each
 * pixel and comparing it to the threshold argument. When the gradient exceeds
 * the threshold, the pixel is replaced by black, otherwise white.
 * Alpha is unaffected.
 *
 * For each pixel and channel, the x-gradient and y-gradient are calculated
 * by using the following convolution matrices:
 *     Gx            Gy
 *  -1  0  +1     +1 +2 +1
 *  -2  0  +2      0  0  0
 *  -1  0  +1     -1 -2 -1
 * The convolution matrix are multiplied with the neighbouring pixels'
 * channel values. At edges, the indices are bounded.
 * Suppose the red channel values for the pixel and its neighbours are as
 * follows: 11 22 33 44 55 66 77 88 99 the x-gradient for red is: (-1*11 + 1*33
 * + -2*44 + 2*66 + -1*77 + 1*99).
 *
 * The net gradient for each channel = sqrt(g_x^2 + g_y^2)
 * For the pixel, the net gradient = sqrt(g_red^2 + g_green^2 + g_blue_2)
 */
void filter_edge_detect(struct image *img, void *threshold_arg) {
  struct pixel(*image_data)[img->size_x] =
      (struct pixel(*)[img->size_x])img->px;
  uint8_t threshold = *(uint8_t *)threshold_arg;
  double weights_x[3][3] = {{-1, 0, 1}, {-2, 0, 2}, {-1, 0, 1}};
  double weights_y[3][3] = {{1, 2, 1}, {0, 0, 0}, {-1, -2, -1}};

  /* Iterate over all pixels */
  for (long i = 0; i < img->size_y; i++) {
    for (long j = 0; j < img->size_x; j++) {
      /* TODO: Implement */
      abort(); // remove line
    }
  }
}

/* The filter structure comprises the filter function, its arguments and the
 * image we want to process */
struct filter {
  void (*filter)(struct image *img, void *arg);
  void *arg;
  struct image *img;
};

void execute_filter(struct filter *fil) { fil->filter(fil->img, fil->arg); }

int __attribute__((weak)) main(int argc, char *argv[]) {
  struct filter fil;
  char input[ARG_SIZE];
  char output[ARG_SIZE];
  char command[ARG_SIZE];
  char arg[ARG_SIZE];
  int radius;
  uint8_t threshold;
  long specific_color;
  struct image *img = NULL;
  double weights[] = {0.2125, 0.7154, 0.0721};

  /* Some filters take no arguments, while others have 1 */
  if (argc != 4 && argc != 5) {
    goto error_usage;
  }

  fil.filter = NULL;
  fil.arg = NULL;

  /* Copy arguments for easier reference */
  strncpy(input, argv[1], ARG_SIZE);
  strncpy(output, argv[2], ARG_SIZE);
  strncpy(command, argv[3], ARG_SIZE);

  /* If the filter takes an argument, copy it */
  if (argv[4]) {
    strcpy(arg, argv[4]);
  }

  /* Error when loading a png image */
  if (load_png(input, &img)) {
    printf(input);
    printf(" PNG file cannot be loaded\n");
    exit(1);
  }

  /* Set up the filter structure */
  fil.img = img;

  /* Decode the filter */
  if (!strcmp(command, "grayscale")) {
    fil.filter = filter_grayscale;
    fil.arg = weights;
  } else if (!strcmp(command, "negative")) {
    fil.arg = NULL;
    fil.filter = filter_negative;
  } else if (!strcmp(command, "blur")) {
    /* Bad filter radius will just be interpretted as 0 - no change to the image
     */
    radius = atoi(arg);
    fil.filter = filter_blur;
    fil.arg = &radius;
  } else if (!strcmp(command, "specific_color")) {

    char *end_ptr;
    long tmp_specific_color = strtol(arg, &end_ptr, 16);

    if (tmp_specific_color < 0) {
      goto error_usage;
    } else {
      specific_color = tmp_specific_color;
    }

    if (*end_ptr) {
      goto error_usage;
    }

    fil.filter = filter_specific_color;
    fil.arg = &specific_color;
  } else if (!strcmp(command, "edge")) {
    char *end_ptr;
    threshold = strtol(arg, &end_ptr, 16);

    if (*end_ptr) {
      goto error_usage;
    }

    fil.filter = filter_edge_detect;
    fil.arg = &threshold;
  }

  /* Invalid filter check */
  if (fil.filter) {
    execute_filter(&fil);
  } else {
    goto error_filter;
  }

  if (store_png(output, img, NULL, 0)) {
    goto error_filter;
  }
  free(img->px);
  free(img);
  return 0;

error_filter:
  free(img->px);
  free(img);
error_usage:
  printf("Usage: %s input_image output_image filter_name [filter_arg]\n",
         argv[0]);
  printf("Filters:\n");
  printf("grayscale\n");
  printf("negative\n");
  printf("blur radius_arg\n");
  printf("specific_color hex_color\n");
  printf("edge hex_threshold\n");
  return 1;
}
