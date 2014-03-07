/**
 * Print the size of the standard types
 */

#include <stdio.h>

static void _print_type_size(const char *name, size_t size)
{
    printf(" * sizeof(%9s) = %lu %s (%2lu bits)\n",
        name, size, (size ==1) ? "byte " : "bytes", size * 8);
}

#define print_type_size(type) _print_type_size(#type, sizeof(type))

int main()
{
    printf("Integer types:\n");
    print_type_size(char);
    print_type_size(short);
    print_type_size(int);
    print_type_size(long);
    print_type_size(long long);
    printf("\nFloat types:\n");
    print_type_size(float);
    print_type_size(double);
    printf("\nPointer types:\n");
    print_type_size(void *);
    print_type_size(int  *);
    return 0;
}
