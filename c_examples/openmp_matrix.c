/**
 * Implement some parallel algorithms operating on matrixes with OpenMP
 */
#include <errno.h>
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Output a string to standard output without any buffering
 */
static void print_nobuf(const char *string)
{
    size_t len = strlen(string);
    while (len > 0) {
        ssize_t count = write(STDOUT_FILENO, string, len);
        if (count == -1 && errno == -EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        string += count;
        len -= count;
    }
}

/**
 * Malloc and exit if it failed
 */
static void* malloc_nofail(size_t size)
{
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "malloc: failed to allocate %lu bytes",
                (unsigned long)size);
        exit(1);
    }
    return ptr;
}

/**
 * Fill a square matrix with a value
 */
static void fill_square_matrix(double *matrix, size_t size, double value)
{
    size_t i, j;
    /* Use static schedule (default) */
    #pragma omp parallel for private(i, j)
    for (i = 0; i < size; i++) {
        for (j = 0; j < size; j++) {
            matrix[i * size + j] = value;
        }
    }
}

/**
 * Initialize a list of vectors
 */
static void init_vector_list(double *vectors, size_t size, size_t dim)
{
    size_t i, j;
    #pragma omp parallel for private(i, j)
    for (i = 0; i < size; i++) {
        for (j = 0; j < dim; j++) {
            vectors[i * dim + j] = ((double) i) + ((double) j + 1) / 100.;
        }
    }
}

/**
 * Sum the values of a square matrix
 */
static double sum_square_matrix(const double *matrix, size_t size)
{
    size_t i_j;
    double sum = 0;
    #pragma omp parallel for private(i_j) reduction(+:sum)
    for (i_j = 0; i_j < size * size; i_j++) {
        sum += matrix[i_j];
    }
    return sum;
}

/**
 * Compute the squared euclidean distance of vectors in a square matrix
 * Here are several ways of implementing this:
 *  1. Compute separately each cell in matrix
 *  2. Compute by triangles
 */
static void sq_euclidean_distance1(
    double *matrix, const double *vectors, size_t size, size_t dim)
{
    size_t i_j;
    #pragma omp parallel for private(i_j)
    for (i_j = 0; i_j < size * size; i_j++) {
        size_t i = i_j / size;
        size_t j = i_j % size;
        size_t k;
        double dist = 0;
        for (k = 0; k < dim; k++) {
            double diff = vectors[i * dim + k] - vectors[j * dim + k];
            dist += diff * diff;
        }
        matrix[i_j] = dist;
    }
}

static void sq_euclidean_distance2(
    double *matrix, const double *vectors, size_t size, size_t dim)
{
    size_t i;
    #pragma omp parallel for private(i)
    for (i = 0; i < size; i++) {
        size_t j;
        matrix[i * size + i] = 0;
        for (j = i + 1; j < size; j++) {
            size_t k;
            double dist = 0;
            for (k = 0; k < dim; k++) {
                double diff = vectors[i * dim + k] - vectors[j * dim + k];
                dist += diff * diff;
            }
            matrix[i * size + j] = dist;
            matrix[j * size + i] = dist;
        }
    }
}

int main()
{
    const size_t size = 10000, dim = 2;
    double *matrix;
    double *vectors;

    /* Test that everything is fine */
    print_nobuf("OpenMP threads:");
    #pragma omp parallel
    {
        int this_thread = omp_get_thread_num();
        int num_threads = omp_get_num_threads();
        char buffer[sizeof(" [/]") + 2 * 11];
        snprintf(buffer, sizeof(buffer), " [%d/%d]", this_thread, num_threads);
        print_nobuf(buffer);
    }
    print_nobuf("\n");

    /* Allocate a big matrix and 2 lists of vectors */
    matrix = malloc_nofail(size * size * sizeof(double));
    vectors = malloc_nofail(size * dim * sizeof(double));

    /* Initialization */
    fill_square_matrix(matrix, size, 0);
    init_vector_list(vectors, size, 2);

    /* Computations */
    sq_euclidean_distance1(matrix, vectors, size, dim);
    printf("1: sum(eucl_dist(vects)) = %f\n", sum_square_matrix(matrix, size));
    sq_euclidean_distance2(matrix, vectors, size, dim);
    printf("2: sum(eucl_dist(vects)) = %f\n", sum_square_matrix(matrix, size));

    /* Free the mallocs */
    free(matrix);
    free(vectors);
    return 0;
}
