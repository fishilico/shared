/**
 * Simple program which can be verified by Frama-C
 *
 * Documentations:
 * * http://frama-c.com/download/frama-c-user-manual.pdf
 * * http://frama-c.com/download/rte-manual-Neon-20140301.pdf
 * * http://frama-c.com/download/acsl-implementation-Neon-20140301.pdf
 * * http://why3.lri.fr/
 * * http://why.lri.fr/provers.html
 * * http://www.fokus.fraunhofer.de/de/sqc/_download_sqc/ACSL-by-Example.pdf
 */
#include <stddef.h>

/*@ axiomatic IsEqual {
  @ predicate isequallab{L1,L2}(char *s1, char *s2, integer n) =
  @   \forall integer i; 0 <= i < n ==> \at(s1[i], L1) == \at(s2[i], L2);
  @
  @ predicate isequal{L}(char *s1, char *s2, integer n) =
  @    isequallab{L,L}(s1, s2, n);
  @ }
  @*/

/*@ requires valid_dst: \valid(((char*)dest) + (0..n - 1));
  @ requires valid_src: \valid_read(((char*)src) + (0..n - 1));
  @ requires separated_mem: \separated(((char*)dest) + (0..n - 1), ((char*)src) + (0..n - 1));
  @ assigns ((char*)dest)[0..n - 1] \from ((char*)src)[0..n - 1];
  @ ensures isequallab{Here,Old}((char*)dest, (char*)src, n);
  @ ensures isequallab{Here,Old}((char*)src, (char*)src, n);
  @ ensures \result == dest;
  @*/
static void* memcpy(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;
    if (n) {
        /*@ ghost size_t i = 0; */
        /*@ loop invariant 0 < n <= \at(n, Pre);
          @ loop invariant i == \at(n, Pre) - n;
          @ loop invariant d == (char*)dest + i;
          @ loop invariant s == (char*)src + i;
          @ loop invariant isequallab{Here,Pre}((char*)src, (char*)src, \at(n, Pre));
          @ loop invariant isequal((char*)dest, (char*)src, i);
          @ loop assigns d, i, n, s, ((char*)dest)[0..\at(n, Pre) - 1];
          @ loop variant n;
          @*/
        do {
            /*@ ghost entry: */
            /*@ assert isequallab{Here,entry}((char*)dest, (char*)src, i); */
            *(d++) = *(s++);
            /*@ assert isequallab{Here,entry}((char*)dest, (char*)src, i); */
            /*@ assert isequallab{Here,entry}((char*)src, (char*)src, \at(n, Pre)); */
            /*@ ghost i++; */
        } while (--n);
    }
    return dest;
}

/*@ requires valid_pa: \valid(pa);
  @ requires valid_pb: \valid(pb);
  @ assigns *pa \from *pb;
  @ assigns *pb \from *pa;
  @ ensures *pa == \old(*pb);
  @ ensures *pb == \old(*pa);
  @*/
static void swap_int(int *pa, int *pb)
{
    int tmp = *pa;
    *pa = *pb;
    *pb = tmp;
}

/*@ assigns \nothing;
  @ ensures \result == 0;
  @*/
int main(void)
{
    int a, b;
    char buffer1[42], buffer2[20];
    size_t i;

    /*@ loop invariant 0 <= i <= sizeof(buffer1);
      @ loop invariant \forall integer j; 0 <= j < i ==> buffer1[j] == j;
      @ loop assigns i, buffer1[0..sizeof(buffer1) - 1];
      @ loop variant sizeof(buffer1) - i;
      @*/
    for (i = 0; i < sizeof(buffer1); i++) {
        buffer1[i] = (char)i;
    }
    memcpy(buffer2, buffer1, sizeof(buffer2));
    a = buffer2[10];
    b = buffer2[0];
    swap_int(&a, &b);
    return a;
}
