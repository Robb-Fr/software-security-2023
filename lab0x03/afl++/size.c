#include <stdio.h>
#include "pngparser.h"

int main(int argc, char *argv[])
{
    struct image *img = NULL;

    if (argc != 2) {
        return 1;
    }

    /* Name the arguments */

    const char *input_name = argv[1];

    if (load_png(input_name, &img)) {
        return 1;
    }

    printf("Image dimensions: %hux%hu\n", img->size_x, img->size_y);
    free(img->px);
    free(img);
    return 0;
}