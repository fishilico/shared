#include <assert.h>
#include "cffi_example.h"

char CFFI_EXAMPLE_API helloworld[] = "Hello, world!";

int CFFI_EXAMPLE_API get_answer(void)
{
    return 42;
}

void CFFI_EXAMPLE_API matrix_add_coords(double *matrix, unsigned int lines, unsigned int cols)
{
    unsigned int i, j;
    for (i = 0; i < lines; i++) {
        for (j = 0; j < cols; j++) {
            matrix[i * cols + j] += (double)i + ((double)j) / 100;
        }
    }
}

void CFFI_EXAMPLE_API transpose_square_matrix(double *matrix, unsigned int n)
{
    unsigned int i, j;
    for (i = 0; i < n - 1; i++) {
        for (j = i + 1; j < n; j++) {
            double t = matrix[i * n + j];
            matrix[i * n + j] = matrix[j * n + i];
            matrix[j * n + i] = t;
        }
    }
}

void CFFI_EXAMPLE_API scalar_mul_matrix(
    double *matrix,
    unsigned long shape0, unsigned long shape1,
    unsigned long stride, double scalar)
{
    unsigned long i, j;
    for (i = 0; i < shape0; i++) {
        for (j = 0; j < shape1; j++) {
            matrix[i * stride + j] = scalar * matrix[i * stride + j];
        }
    }
}
