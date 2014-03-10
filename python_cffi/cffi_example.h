#ifndef CFFI_EXAMPLE_H
#define CFFI_EXAMPLE_H

/* Shared library symbols */
#if defined _WIN32 || defined __CYGWIN__
    #ifdef _CFFI_EXAMPLE_EXPORTS
        #define CFFI_EXAMPLE_API __declspec(dllexport)
    #else
        #define CFFI_EXAMPLE_API __declspec(dllimport)
    #endif
#elif __GNUC__ >= 4
    #define CFFI_EXAMPLE_API __attribute__((visibility("default")))
#else
    #define CFFI_EXAMPLE_API
#endif

struct stringpair {
    char *str1;
    char *str2;
};

extern char CFFI_EXAMPLE_API helloworld[];

extern int CFFI_EXAMPLE_API get_answer(void);

extern void CFFI_EXAMPLE_API matrix_add_coords(double *matrix, unsigned int lines, unsigned int cols);

extern void CFFI_EXAMPLE_API transpose_square_matrix(double *matrix, unsigned int n);

#endif /* CFFI_EXAMPLE_H */
