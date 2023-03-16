#include "pngparser.h"

void filter_grayscale(struct image *img, void *weight_arr);
void filter_blur(struct image *img, void *r);
void filter_negative(struct image *img, void *noarg);
void filter_transparency(struct image *img, void *transparency);
void filter_sepia(struct image *img, void *depth_arg);
void filter_bw(struct image *img, void *threshold_arg);
void filter_edge_detect(struct image *img, void *threshold_arg);
void filter_keying(struct image *img, void *arg);
