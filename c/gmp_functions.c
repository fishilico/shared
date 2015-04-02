/**
 * Use some functions of the GNU Multiple Precision Arithmetic Library (GMP)
 *
 * Documentation links:
 * * https://gmplib.org/manual/ GNU MP library manual
 * * http://web.mit.edu/gnu/doc/html/gmp_4.html GNU MP Integer Functions
 * * http://rosettacode.org/wiki/Modular_inverse
 */
#include <assert.h>
#include <gmp.h>
#include <stdio.h>

/**
 * Modular exponentiation: result = base ^ exp modulo mod
 */
static void modexp(mpz_ptr result, mpz_srcptr base, mpz_srcptr exp, mpz_srcptr mod)
{
    mpz_t b, e, exp_lsb;

    mpz_init_set(b, base);
    mpz_init_set(e, exp);
    mpz_init(exp_lsb);
    mpz_set_ui(result, 1); /* r = 1 */

    while (mpz_cmp_ui(e, 0) > 0) { /* while (e > 0) */
        mpz_mod_2exp(exp_lsb, e, 1);
        if (mpz_cmp_ui(exp_lsb, 0) != 0) { /* if (e % 2) */
            mpz_mul(result, result, b);
            mpz_mod(result, result, mod); /* r = r * b % m */
        }
        mpz_div_2exp(e, e, 1); /* e >>= 1 */
        mpz_mul(b, b, b);
        mpz_mod(b, b, mod); /* b = b * b % m */
    }
    mpz_clear(b);
    mpz_clear(e);
    mpz_clear(exp_lsb);
}

/**
 * Modular inversion: compute result so that: result * num modulo mod = 1
 *
 * Hypotheses: num > 0, mod >= 2, gcd(num, mod) = 1
 */
static void invmod(mpz_ptr result, mpz_srcptr num, mpz_srcptr mod)
{
    mpz_t a, b, s, q, tmp;

    /* Find (r, s) so that: r * a + s * b = 1 */
    mpz_init_set(a, num);
    mpz_init_set(b, mod);
    mpz_init_set_ui(s, 0);
    mpz_set_ui(result, 1);
    mpz_init(q);
    mpz_init(tmp);

    while (mpz_cmp_ui(a, 1) > 0) { /* while (a > 1) */
        mpz_divmod(q, tmp, a, b);
        mpz_set(a, b);
        mpz_set(b, tmp); /* (a, b) = (b, a % b) */
        mpz_mul(tmp, q, s);
        mpz_sub(tmp, result, tmp);
        mpz_set(result, s);
        mpz_set(s, tmp); /* (r, s) = (s, r - (a / b) * s) */
    }

    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(s);
    mpz_clear(q);
    mpz_clear(tmp);
}

int main(void)
{
    mpz_t base, encbase, e, inve, p, p_minus_1, tmp;
    unsigned long i;

    mpz_init_set_str(base, "12345678901234567890", 10);
    mpz_init_set_str(e, "10001", 16);
    mpz_init(tmp);

    /* Build 27! + 1 prime number
     * Check that this is prime on http://magma.maths.usyd.edu.au/calc/ with:
     *     IsPrime(10888869450418352160768000001)
     */
    mpz_init_set_str(p, "1", 10);
    for (i = 2; i <= 27; i++) {
        mpz_mul_ui(p, p, i);
    }
    mpz_add_ui(p, p, 1);
    gmp_printf("p = 27! + 1 = %Zd\n", p);
    /* p = 27! + 1 = 10888869450418352160768000001 */

    /* Check that base ^ (p-1) mod p = 1 (Little Fermat Theorem) */
    mpz_init(p_minus_1);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_powm(tmp, base, p_minus_1, p);
    gmp_printf("%Zd ^ (p - 1) mod p = %Zd\n", base, tmp);
    assert(mpz_cmp_ui(tmp, 1) == 0);

    /* Run custom modexp */
    mpz_init(encbase);
    modexp(encbase, base, e, p);
    gmp_printf("%Zd ^ %Zd mod p = %Zd\n", base, e, encbase);
    /* 12345678901234567890 ^ 65537 mod p = 7267625541209636446986898073 */

    /* Run GMP modexp and check the previous result */
    mpz_powm(tmp, base, e, p);
    assert(mpz_cmp(encbase, tmp) == 0);

    /* Invert the exponent, modulo p - 1 */
    mpz_init(inve);
    invmod(inve, e, p_minus_1);
    gmp_printf("inve = %Zd ^ -1 mod (p - 1) = %Zd\n", e, inve);
    /* inve = 65537 ^ -1 mod (p - 1) = 5149770490192056780490473473 */

    /* Check the result */
    mpz_mul(tmp, e, inve);
    mpz_mod(tmp, tmp, p_minus_1);
    assert(mpz_cmp_ui(tmp, 1) == 0);

    /* Reverse the previous modexp */
    modexp(tmp, encbase, inve, p);
    gmp_printf("%Zd ^ inve mod p = %Zd\n", encbase, tmp);
    assert(mpz_cmp(tmp, base) == 0);
    /* 7267625541209636446986898073 ^ inve mod p = 12345678901234567890 */

    mpz_clear(base);
    mpz_clear(encbase);
    mpz_clear(e);
    mpz_clear(inve);
    mpz_clear(p);
    mpz_clear(p_minus_1);
    mpz_clear(tmp);
    return 0;
}
