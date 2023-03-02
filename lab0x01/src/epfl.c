#include "pngparser.h"
#include <math.h>
#include <string.h>

/**
  This program adds our wonderful EPFL logo to the image passed via the
  argument.
*/

int main(int argc, char *argv[]) {
  struct image *img;

  /* Check if the number of arguments is correct otherwise exit */
  if (argc != 7) {
    printf("Usage: %s input_image output_image top_left_x top_left_y size "
           "hex_color\n",
           argv[0]);
  }

  /* Rename arguments for easier reference */
  char *input = argv[1];
  char *output = argv[2];

  /* Decode the top left of the EPFL logo. Invalid values are decoded as 0 */
  int top_left_x = atoi(argv[3]);
  int top_left_y = atoi(argv[4]);

  /* Invalid size will just be interpreted as 1 */
  int size = atoi(argv[5]);
  if (size < 1) {
    size = 1;
  }

  /* Invalid color will be interpreted as black */
  char *end_ptr;
  long hex_color = strtol(argv[6], &end_ptr, 16);
  if (*end_ptr || strlen(argv[6]) != 6 || hex_color < 0) {
    hex_color = 0;
  }

  if (load_png(input, &img)) {
    return 1;
  }

  unsigned height = img->size_y;
  unsigned width = img->size_x;

  struct pixel(*image_data)[width] = (struct pixel(*)[width])img->px;

  /*
  Logo:
  ███░███░███░█░░
  █░░░█░█░█░░░█░░
  ░█░░███░░█░░█░░
  █░░░█░░░█░░░█░░
  ███░█░░░█░░░███
  size 5x15
  Each column of the logo is encoded as a 32 bit number.
  Most significant bit at the top.
  A full column (e.g., first column of E) => 11111 => 31
  */
  unsigned logo_height = 5;
  unsigned logo_width = 15;
  unsigned char epfl[15] = {27, 21, 17, 0, 31, 20, 28, 0,
                            27, 20, 16, 0, 31, 1,  1};
  // Adjustment for the logo if we go out of range
  unsigned char logo_adj[15] = {0, 0,   0,  0, -15, 11, -12, 0,
                                4, -16, 15, 0, -12, 20, 24};

  // We'll go column by column, painting the logo when we are in the correct
  // columns.
  unsigned j = top_left_x;
  while (j < width) {
    unsigned i = top_left_y;
    // Check if we are in a column to draw
    if (j >= top_left_x && j < top_left_x + logo_width) {
      // Find column index in logo
      unsigned j_logo = (j - top_left_x) / size;
      // Ensure that we do not go below the bottom of the picture
      if (i + size * logo_height >= height) {
        // If we do, move the logo up to the top.
        epfl[j_logo] += logo_adj[j_logo];
        i = logo_adj[j_logo] = 0;
      }

      // Iterate over the height of the logo with i_logo
      for (int i_logo = 0; i_logo < size * logo_height; i_logo++) {
        // i_logo / size is between 0 and logo_height and when shifted get us
        // the correct bit mask for the logo int.
        if (epfl[j_logo] & (16 >> i_logo / size)) {
          /* The fancy syntax here is just masking the corresponding bits
           * If the color is RRGGBB, performing AND with 0xff0000 will isolate
           * the bytes representing red. We then shift them to the right to
           * bring them into the correct range
           */
          image_data[i + i_logo][j].red = (hex_color & 0xff0000) >> 16;
          image_data[i + i_logo][j].green = (hex_color & 0x00ff00) >> 8;
          image_data[i + i_logo][j].blue = (hex_color & 0x0000ff);
          image_data[i + i_logo][j].alpha = 0xff;
        }
      }
    }
    j++;
  }

  if (store_png(output, img, NULL, 0)) {
    free(img->px);
    free(img);
    return 1;
  }
  free(img->px);
  free(img);
  return 0;
}
