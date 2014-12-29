/**
 * Do some operations with floats in assembly language.
 *
 * On x86 CPUs, it uses x87 instructions, a subset of the x86 instruction set
 * related to floating-point numbers.
 *
 * Documentation:
 * * https://gcc.gnu.org/onlinedocs/gcc/Machine-Constraints.html (GCC asm)
 * * https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/ieee754/ieee754.h;hb=HEAD
 *   (ieee754_float and ieee754_double definitions)
 * * http://csapp.cs.cmu.edu/public/waside/waside-x87.pdf
 * * https://courses.engr.illinois.edu/ece390/books/artofasm/CH14/CH14-1.html
 *  (Art of Assembly Language, "Floating Point Arithmetic")
 */
#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>

static float add_f(float x, float y)
{
#if defined(__x86_64__)
    /* Use XMM registers (SSE, Streaming SIMD Extensions) */
    __asm__ ("addss %1, %0" : "+x"(x) : "x"(y));
    return x;
#elif defined(__i386__)
    /* "t" is st(0) and "u" st(1) */
    __asm__ ("fadds %1" : "+t"(x) : "fm"(y));
    return x;
#else
#    warning "add_f not yet implemented in asm"
    return x + y;
#endif
}

static double add_d(double x, double y)
{
#if defined(__x86_64__)
    __asm__ ("addsd %1, %0" : "+x"(x) : "x"(y));
    return x;
#elif defined(__i386__)
    __asm__ ("faddl %1" : "+t"(x) : "m"(y));
    return x;
#else
#    warning "add_d not yet implemented in asm"
    return x + y;
#endif
}

static int toint_f(float x)
{
    int i;
#if defined(__x86_64__)
    /* Convert scalar single-precision floating-point value (with truncation) to signed integer */
    /* Note: "clang as" has difficulties when the output is a memory, so force it to be a reg. */
    __asm__ ("cvttss2si %1, %0" : "=r"(i) : "x"(x));
#elif defined(__i386__)
    __asm__ ("flds %1 ; fistps %0" : "=m"(i) : "tm"(x));
#else
#    warning "toint_f not yet implemented in asm"
    i = (int)x;
#endif
    return i;
}

static int toint_d(double x)
{
    int i;
#if defined(__x86_64__)
    /* Convert scalar double-precision floating-point value (with truncation) to signed integer */
    __asm__ ("cvttsd2si %1, %0" : "=r"(i) : "x"(x));
#elif defined(__i386__)
    __asm__ ("fldl %1 ; fistpl %0" : "=m"(i) : "tm"(x));
#else
#    warning "toint_d not yet implemented in asm"
    i = (int)x;
#endif
    return i;
}

static float sqrt_f(float x)
{
#if defined(__x86_64__)
    __asm__ ("sqrtss %1, %0" : "+x"(x));
    return x;
#elif defined(__i386__)
    __asm__ ("fsqrt" : "+t"(x));
    return x;
#else
#    warning "sqrt_f not yet implemented in asm"
    return fsqrt(x);
#endif
}

static double sqrt_d(double x)
{
#if defined(__x86_64__)
    __asm__ ("sqrtsd %1, %0" : "+x"(x));
    return x;
#elif defined(__i386__)
    __asm__ ("fsqrt": "+t"(x));
    return x;
#else
#    warning "sqrt_f not yet implemented in asm"
    return fsqrt(x);
#endif
}

static void sincos_f(float angle, float *s, float *c)
{
#if defined(__x86_64__) || defined(__i386__)
    __asm__ ("fsincos" : "=t"(*c), "=u"(*s) : "0"(angle));
#else
#    warning "sincos_f not yet implemented in asm"
    *s = fsin(angle);
    *c = fcos(angle);
#endif
}

/**
 * Fast inverse square root
 * http://en.wikipedia.org/wiki/Fast_inverse_square_root
 */
static float invsqrt_f(float x)
{
    int32_t i;
    float xhalf = x * .5f;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
    i = *(int32_t *)&x;
    i = 0x5f3759df - (i >> 1);
    x = *(float *)&i;
#pragma GCC diagnostic pop
    x = x * (1.5f - (xhalf * x * x));
    x = x * (1.5f - (xhalf * x * x));
    return x;
}

static double invsqrt_d(double x)
{
    int64_t i;
    double xhalf = x * .5;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
    i = *(int64_t *)&x;
    i = 0x5fe6eb50c7b537a9LL - (i >> 1);
    x = *(double *)&i;
#pragma GCC diagnostic pop
    x = x * (1.5 - (xhalf * x * x));
    return x;
}

/* Run some tests */
#define _ok(description, test, format, result, expected) \
    do { \
        if (test) { \
            printf("[ OK ] %s = %" format "\n", description, result); \
        } else { \
            printf("[FAIL] %s = %" format ", expected %" format "\n", description, result, expected); \
            retval = 1; \
        } \
    } while (0)

#define _ok_i(description, result, expected) \
    do { \
        const int r = (result), e = (expected); \
        _ok(description, (r == e), "d", r, e); \
    } while (0)
#define ok_i(fctcall, value) _ok_i(#fctcall, (fctcall), (value))

#define _ok_f(description, result, expected) \
    do { \
        const float r = (result), e = (expected); \
        _ok(description, (fabsf(r - e) < 1.e-6), "g", r, e); \
    } while (0)
#define ok_f(fctcall, value) _ok_f(#fctcall, (fctcall), (value))

#define _ok_d(description, result, expected) \
    do { \
        const double r = (result), e = (expected); \
        _ok(description, (fabs(r - e) < 1.e-6), "g", r, e); \
    } while (0)
#define ok_d(fctcall, value) _ok_d(#fctcall, (fctcall), (value))

#define ok_nan(fctcall) _ok(#fctcall, isnan(fctcall), "f", (fctcall), 0./0.)

static int check_constants(void)
{
    int retval = 0;
#if defined(__x86_64__) || defined(__i386__)
    float f;

    __asm__ ("fldz" : "=t"(f));
    _ok_f("fldz", f, 0);
    __asm__ ("fld1" : "=t"(f));
    _ok_f("fld1", f, 1);
    __asm__ ("fldpi" : "=t"(f));
    _ok_f("fldpi", f, (float)M_PI);
    __asm__ ("fldl2e" : "=t"(f));
    _ok_f("fldl2e = log_2(e)", f, (float)M_LOG2E);
    __asm__ ("fldln2" : "=t"(f));
    _ok_f("fldln2 = log_e(2)", f, (float)M_LN2);
    __asm__ ("fldl2t" : "=t"(f));
    _ok_f("fldl2t = log_2(10)", f, (float)M_LN10 / (float)M_LN2);
    __asm__ ("fldlg2" : "=t"(f));
    _ok_f("fldlg2 = log_10(2)", f, (float)M_LN2 / (float)M_LN10);
#else
#    warning "no constant operation implemented yet"
#endif
    return retval;
}

int main(void)
{
    int retval = 0;
    float cf, sf;

    retval = check_constants();

    ok_f(add_f(3, 4), 7);
    ok_f(add_f(-10, 10), 0);

    ok_d(add_d(100, 42), 142);
    ok_d(add_d(60, -18), 42);

    ok_f(sqrt_f(100), 10);
    ok_f(sqrt_f(1764), 42);
    ok_d(sqrt_d(2), M_SQRT2);
    ok_d(sqrt_d(1e6), 1000);
    ok_nan(sqrt_f(-1));

    sincos_f(0, &sf, &cf);
    _ok_f("sincos_f(0).sin", sf, 0);
    _ok_f("sincos_f(0).cos", cf, 1);
    sincos_f((float)(M_PI / 2), &sf, &cf);
    _ok_f("sincos_f(PI/2).sin", sf, 1);
    _ok_f("sincos_f(PI/2).cos", cf, 0);
    sincos_f((float)(M_PI / 3), &sf, &cf);
    _ok_f("sincos_f(PI/3).sin", sf, sqrt_f(3) / 2);
    _ok_f("sincos_f(PI/3).cos", cf, 0.5);

    ok_f(invsqrt_f(10000), .01f);
    ok_i(toint_f(invsqrt_f(1.f / 1764.f) + .01f), 42);
    ok_i(toint_d(invsqrt_d(1. / 1764.) + .06), 42);
    return retval;
}
