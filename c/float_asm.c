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
 *   (Art of Assembly Language, "Floating Point Arithmetic")
 * * http://mindplusplus.wordpress.com/2012/11/20/comparing-the-x87-and-arm-vfp/
 *   (Comparing the x87 and ARM VFP)
 */

/* With -ansi on Windows, some float functions like isnan are not defined */
#if defined(__STRICT_ANSI__) && (defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64))
#    undef __STRICT_ANSI__
#endif
#if !defined(_GNU_SOURCE) && (defined(__linux__) || defined(__unix__) || defined(__posix__))
#    define _GNU_SOURCE /* for math constants and float features */
#endif

#include <math.h>
#include <stdint.h>
#include <stdio.h>

static float add_f(float x, float y)
{
#if defined(__x86_64__)
    /* Use XMM registers (SSE, Streaming SIMD Extensions) */
    __asm__ __volatile__ ("addss %1, %0" : "+x"(x) : "x"(y));
#elif defined(__i386__)
    /* "t" is st(0) and "u" st(1) */
    __asm__ __volatile__ ("fadds %1" : "+t"(x) : "fm"(y));
#elif defined(__arm__) && defined(__VFP_FP__)
    /* Use VFP floating-point registers */
    __asm__ __volatile__ ("vadd.f32 %0, %0, %1" : "+w"(x) : "w"(y));
#else
#    warning "add_f not yet implemented in asm"
    x += y;
#endif
    return x;
}

static double add_d(double x, double y)
{
#if defined(__x86_64__)
    __asm__ __volatile__ ("addsd %1, %0" : "+x"(x) : "x"(y));
#elif defined(__i386__)
    __asm__ __volatile__ ("faddl %1" : "+t"(x) : "m"(y));
#elif defined(__arm__) && defined(__VFP_FP__)
    __asm__ __volatile__ ("vadd.f64 %P0, %P0, %P1" : "+w"(x) : "w"(y));
#else
#    warning "add_d not yet implemented in asm"
    x += y;
#endif
    return x;
}

static int toint_f(float x)
{
    int i;
#if defined(__x86_64__)
    /* Convert scalar single-precision floating-point value (with truncation) to signed integer */
    /* Note: "clang as" has difficulties when the output is a memory, so force it to be a reg. */
    __asm__ __volatile__ ("cvttss2si %1, %0" : "=r"(i) : "x"(x));
#elif defined(__i386__)
    /* Use flds for single-precision float and fistpl for 32-bit integer (fistps would mean 16-bit) */
    __asm__ __volatile__ ("flds %1 ; fistpl %0" : "=m"(i) : "m"(x));
#elif defined(__arm__) && defined(__VFP_FP__) && !defined(__clang__)
    /* clang 3.5.0 fails with "error: couldn't allocate output register for constraint 'w'" */
    __asm__ __volatile__ ("vcvt.s32.f32 %0, %1" : "=w"(i) : "w"(x));
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
    __asm__ __volatile__ ("cvttsd2si %1, %0" : "=r"(i) : "x"(x));
#elif defined(__i386__)
    __asm__ __volatile__ ("fldl %1 ; fistpl %0" : "=m"(i) : "m"(x));
#elif defined(__arm__) && defined(__VFP_FP__) && !defined(__clang__)
    __asm__ __volatile__ ("vcvt.s32.f64 %0, %P1" : "=w"(i) : "w"(x));
#else
#    warning "toint_d not yet implemented in asm"
    i = (int)x;
#endif
    return i;
}

static float sqrt_f(float x)
{
    float s;
#if defined(__x86_64__)
    __asm__ __volatile__ ("sqrtss %1, %0" : "=x"(s) : "x"(x));
#elif defined(__i386__)
    s = x;
    __asm__ __volatile__ ("fsqrt" : "+t"(s));
#elif defined(__arm__) && defined(__VFP_FP__)
    __asm__ __volatile__ ("vsqrt.f32 %0, %1" : "=w"(s) : "w"(x));
#else
#    warning "sqrt_f not yet implemented in asm"
    s = sqrtf(x);
#endif
    return s;
}

static double sqrt_d(double x)
{
    double s;
#if defined(__x86_64__)
    __asm__ __volatile__ ("sqrtsd %1, %0" : "=x"(s) : "x"(x));
#elif defined(__i386__)
    s = x;
    __asm__ __volatile__ ("fsqrt": "+t"(s));
#elif defined(__arm__) && defined(__VFP_FP__)
    __asm__ __volatile__ ("vsqrt.f64 %P0, %P1" : "=w"(s) : "w"(x));
#else
#    warning "sqrt_d not yet implemented in asm"
    s = sqrt(x);
#endif
    return s;
}

/* Here are some implementations of sincosf:
 * * https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86_64/fpu/s_sincosf.S;hb=HEAD
 *   (x86_64 glibc)
 * * https://code.google.com/p/math-neon/source/browse/trunk/math_sincosf.c
 *   (ARM Neon)
 *
 * To compute sin(x), here are some implementations:
 * * https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/ieee754/flt-32/k_sinf.c;hb=HEAD
 *   (glibc, after interval reduction)
 * * https://code.google.com/p/math-neon/source/browse/trunk/math_sinf.c
 *   (ARM Neon)
 */
static void sincos_f(float angle, float *s, float *c)
{
#if defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__ ("fsincos" : "=t"(*c), "=u"(*s) : "0"(angle));
#else
    /* gcc -O2 groups these calls to a single sincosf */
    *s = sinf(angle);
    *c = cosf(angle);
#endif
}

/**
 * Fast inverse square root
 * http://en.wikipedia.org/wiki/Fast_inverse_square_root
 *
 * This requires disabling strict aliasing warnings, and gcc<4.5 does not
 * support diagnostic push/pop.
 */
#if defined(__GNUC__)
#    define HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH ((__GNUC__ << 16) + __GNUC_MINOR__ >= 0x40005)
#else
#    define HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH 1
#endif
#if HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH
#    pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
static float invsqrt_f(float x)
{
    int32_t i;
    float xhalf = x * .5f;

    i = *(int32_t *)&x;
    i = 0x5f3759df - (i >> 1);
    x = *(float *)&i;
    x = x * (1.5f - (xhalf * x * x));
    x = x * (1.5f - (xhalf * x * x));
    return x;
}

static double invsqrt_d(double x)
{
    int64_t i;
    double xhalf = x * .5;

    i = *(int64_t *)&x;
    i = 0x5fe6eb50c7b537a9LL - (i >> 1);
    x = *(double *)&i;
    x = x * (1.5 - (xhalf * x * x));
    return x;
}
#if HAVE_PRAGMA_GCC_DIAGNOSTIC_PUSH
#    pragma GCC diagnostic pop
#endif

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
        _ok(description, (fabsf(r - e) < 1.e-6f), "g", (double)r, (double)e); \
    } while (0)
#define ok_f(fctcall, value) _ok_f(#fctcall, (fctcall), (value))

#define _ok_d(description, result, expected) \
    do { \
        const double r = (result), e = (expected); \
        _ok(description, (fabs(r - e) < 1.e-6), "g", r, e); \
    } while (0)
#define ok_d(fctcall, value) _ok_d(#fctcall, (fctcall), (value))

/* musl does not support isnanf and glibc isnan causes a -Wdouble-promotion
 * warning with clang
 */
#if !defined(isnanf) && !defined(__GLIBC__)
#    define isnanf(value) isnan((float)(value))
#endif
#define ok_nan(fctcall) _ok(#fctcall, isnanf(fctcall), "f", (double)(fctcall), (double)NAN)

static int check_constants(void)
{
    int retval = 0;
#if defined(__x86_64__) || defined(__i386__)
    float f;

    __asm__ __volatile__ ("fldz" : "=t"(f));
    _ok_f("fldz", f, 0);
    __asm__ __volatile__ ("fld1" : "=t"(f));
    _ok_f("fld1", f, 1);
    __asm__ __volatile__ ("fldpi" : "=t"(f));
    _ok_f("fldpi", f, (float)M_PI);
    __asm__ __volatile__ ("fldl2e" : "=t"(f));
    _ok_f("fldl2e = log_2(e)", f, (float)M_LOG2E);
    __asm__ __volatile__ ("fldln2" : "=t"(f));
    _ok_f("fldln2 = log_e(2)", f, (float)M_LN2);
    __asm__ __volatile__ ("fldl2t" : "=t"(f));
    _ok_f("fldl2t = log_2(10)", f, (float)M_LN10 / (float)M_LN2);
    __asm__ __volatile__ ("fldlg2" : "=t"(f));
    _ok_f("fldlg2 = log_10(2)", f, (float)M_LN2 / (float)M_LN10);
#elif defined(__arm__)
    /* No constant loading in ARM instruction set */
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

    ok_i(toint_f(42.f), 42);
    ok_i(toint_d(1e4), 10000);

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
