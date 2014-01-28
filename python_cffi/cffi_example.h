#ifndef CFFI_EXAMPLE_H
#define CFFI_EXAMPLE_H

struct stringpair {
    char *str1;
    char *str2;
};

extern char *helloworld;

extern int get_answer(void);

extern void matrix_add_coords(double *matrix, unsigned int lines, unsigned int cols);

extern void transpose_square_matrix(double *matrix, unsigned int n);

#endif /* CFFI_EXAMPLE_H */
