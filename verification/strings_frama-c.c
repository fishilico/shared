/**
 * Simple program with string operations which can be verified by Frama-C
 */
#include <limits.h> /* for ULONG_MAX */
#include <stdbool.h> /* for bool */
#include <stddef.h> /* for size_t */

/*@ axiomatic IsEqual {
  @ predicate isequallab{L1,L2}(char *s1, char *s2, integer n) =
  @     \forall integer i; 0 <= i < n ==> \at(s1[i], L1) == \at(s2[i], L2);
  @
  @ predicate isequal{L}(char *s1, char *s2, integer n) =
  @     isequallab{L,L}(s1, s2, n);
  @ }
  @*/

/*@ axiomatic StrLen {
  @ logic integer strlen{L}(char *s)
  @     reads s[0..];
  @
  @ axiom strlen_definition{L}:
  @     \forall char *s; \forall integer i;
  @         0 <= i &&  (\forall integer j; 0 <= j < i ==> s[j] != '\0') && s[i] == '\0'
  @         ==> strlen(s) == i;
  @
  @ axiom strlen_def_nonul{L}:
  @     \forall char *s; \forall integer i; 0 <= i < strlen(s) ==> s[i] != '\0';
  @
  @ axiom strlen_def_endnul{L}:
  @     \forall char *s; 0 <= strlen(s) ==> s[strlen(s)] == '\0';
  @
  @ axiom strlen_sup{L}:
  @     \forall char* s; \forall integer i;
  @         0 <= i && s[i] == '\0' ==> 0 <= strlen(s) <= i;
  @
  @ // TODO: make this a lemma and prove it with the axioms above.
  @ axiom isequal_strlen_lt{L}:
  @   \forall char *s1, *s2; \forall integer n;
  @      isequal(s1, s2, n) && strlen(s2) < n ==> strlen(s1) == strlen(s2);
  @ }
  @*/

/*@ axiomatic ValidString {
  @ predicate valid_string{L}(char *s) =
  @   0 <= strlen(s) <= ULONG_MAX && \valid(s+(0..strlen(s)));
  @
  @ predicate valid_cstring{L}(char *s) =
  @   0 <= strlen(s) <= ULONG_MAX && \valid_read(s+(0..strlen(s)));
  @ }
  @*/

/*@ requires valid_dst: \valid(dest + (0..n - 1));
  @ assigns dest[0..n - 1];
  @ ensures \forall integer i; 0 <= i < n ==> dest[i] == c;
  @*/
static void memset_c(char *dest, char c, size_t n)
{
    size_t i;
    /*@ loop invariant 0 <= i <= n;
      @ loop invariant \forall integer j; 0 <= j < i ==> dest[j] == c;
      @ loop assigns i, dest[0..n - 1];
      @ loop variant n - i;
      @*/
    for (i = 0; i < n; i++) {
        dest[i] = c;
        /*@ assert \forall integer j; 0 <= j <= i ==> dest[j] == c; */
    }
}


/*@ requires valid_dst: \valid(dest + (0..n - 1));
  @ requires valid_src: \valid_read(src + (0..n - 1));
  @ requires separated: \separated(dest + (0..n - 1), src + (0..n - 1));
  @ assigns dest[0..n - 1] \from src[0..n - 1];
  @ ensures isequal(dest, src, n);
  @ ensures isequallab{Here,Old}(src, src, n);
  @*/
static void memcpy_c(char *dest, const char *src, size_t n)
{
    size_t i;
    /*@ loop invariant 0 <= i <= n;
      @ loop invariant isequal(dest, src, i);
      @ loop invariant isequallab{Here,Pre}(src, src, \at(n, Pre));
      @ loop assigns i, dest[0..\at(n,Pre) - 1];
      @ loop variant n - i;
      @*/
    for (i = 0; i < n; i++) {
        ((char*)dest)[i] = ((char*)src)[i];
        /*@ assert isequal(dest, src, i + 1); */
    }
}

/*@ requires valid_string_src: valid_cstring(str);
  @ assigns \nothing;
  @ ensures \result == strlen(str);
  @ ensures \forall integer i; 0 <= i <= \result ==> \valid_read(str + i);
  @ ensures \forall integer i; 0 <= i < \result ==> str[i] != 0;
  @ ensures str[\result] == '\0';
  @*/
static size_t strlen(const char *str)
{
    const char *p = str;
    /*@ ghost size_t c = 0; */
    /*@ loop invariant str <= p;
      @ loop invariant p == str + c;
      @ loop invariant \valid_read(p);
      @ loop invariant \forall integer i; 0 <= i < c ==> str[i] != 0;
      @ loop invariant c <= strlen(str);
      @ loop assigns c, p;
      @*/
    while (*p) {
        p++;
        /*@ ghost c++; */
    }
    return p - str;
}

/*@ requires valid_dst: size == 0 || \valid(dest + (0..size - 1));
  @ requires valid_string_src: valid_cstring(src);
  @ requires separated: \separated(dest + (0..size - 1), src + (0..strlen(src)));
  @ ensures isequallab{Here,Old}(src, src, \old(strlen(src)) + 1);
  @ behavior complete:
  @   assumes strlen(src) < size;
  @   assigns dest[0..strlen(src)] \from src[0..strlen(src)];
  @   ensures isequal(dest, src, \old(strlen(src)) + 1);
  @   ensures valid_cstring(dest);
  @   ensures strlen(dest) == strlen(src);
  @ behavior partial:
  @   assumes 0 < size <= strlen(src);
  @   assigns dest[0..size - 1] \from src[0..size - 1];
  @   ensures isequal(dest, src, size - 1);
  @   ensures dest[size - 1] == '\0';
  @   ensures valid_cstring(dest);
  @   ensures strlen(dest) == size - 1;
  @ behavior nothing:
  @   assumes size == 0;
  @   assigns \nothing;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
static void strlcpy(char *dest, const char *src, size_t size)
{
    /*@ ghost begin: */
    size_t len = strlen(src);
    /*@ ghost size_t srclen = len; */
    if (len < size) {
        /*@ assert len + 1 <= size; */
        /*@ ghost before: */
        memcpy_c(dest, src, len + 1);
        /*@ assert isequal(dest, src, len + 1); */
        /*@ assert \forall integer i; 0 <= i <= len ==> \at(src[i], before) == src[i]; */
    } else if (size != 0) {
        size_t size1 = size - 1;
        /*@ assert size1 < len; */
        /*@ assert \separated(dest + (0..size1), src + (0..srclen)); */
        /*@ assert \forall integer i; 0 <= i < len ==> src[i] != 0; */
        /*@ assert \forall integer i; 0 <= i < size1 ==> src[i] != 0; */
        /*@ assert \forall integer i; 0 <= i <= srclen ==> \at(src[i], begin) == src[i]; */
        /*@ ghost copy: */
        memcpy_c(dest, src, size1);
        /*@ assert isequal(dest, src, size1); */
        /*@ assert \forall integer i; 0 <= i <= srclen ==> \at(src[i], copy) == src[i]; */
        /*@ ghost endnul: */
        dest[size1] = '\0';
        /*@ assert \forall integer i; 0 <= i <= srclen ==> \at(src[i], endnul) == src[i]; */
        /*@ assert \forall integer i; 0 <= i < size1 ==> \at(src[i], endnul) == src[i]; */
        /*@ assert \forall integer i; 0 <= i < size1 ==> \at(dest[i], endnul) == dest[i]; */
        /*@ assert isequal(dest, src, size1); */
        /*@ assert \forall integer i; 0 <= i < size1 ==> src[i] != '\0'; */
        /*@ assert \forall integer i; 0 <= i < size1 ==> dest[i] == src[i] != '\0'; */
        /*@ assert isequal(dest, src, size1); */
        /*@ assert strlen(dest) == size1; */
        /*@ assert \forall integer i; 0 <= i <= srclen ==> \at(src[i], copy) == src[i]; */
        /*@ assert size - 1 == size1; */
        /*@ assert dest[size - 1] == '\0'; */
    }
}

/*@ requires valid_str: \valid_read(str + (0..len));
  @ assigns \nothing;
  @ ensures \result ==> valid_cstring(str);
  @ ensures \result ==> strlen(str) == len;
  @*/
static bool is_valid_cstring(const char *str, size_t len)
{
    size_t i;
    /*@ loop invariant i <= len;
      @ loop invariant \forall integer j; 0 <= j < i ==> str[j] != '\0';
      @ loop assigns i;
      @ loop variant len - i;
      @*/
    for (i = 0; i < len; i++) {
        if (str[i] == '\0') {
            return false;
        }
    }
    return str[len] == '\0';
}

#define HELLO_WORLD_LEN 13

/*@ // TODO: assigns \nothing;
  @ ensures \result == 0;
  @*/
int main(void)
{
    const char helloworld[] = "Hello, world!";
    char buffer_small[6];
    char buffer_big[42];

    /*@ assert HELLO_WORLD_LEN == sizeof(helloworld) - 1; */

    memset_c(buffer_small, 0, sizeof(buffer_small));
    memset_c(buffer_big, 0, sizeof(buffer_big));

    if (!is_valid_cstring((char*)helloworld, HELLO_WORLD_LEN)) {
        return 0;
    }
    /*@ assert valid_cstring((char*)helloworld); */
    /*@ assert strlen((char*)helloworld) == HELLO_WORLD_LEN; */
    /*@ assert \separated(buffer_small + (0..sizeof(buffer_small) - 1), helloworld + (0 .. HELLO_WORLD_LEN)); */
    /*@ assert sizeof(buffer_small) < HELLO_WORLD_LEN; */
    /*@ assert sizeof(buffer_small) < strlen((char*)helloworld); */
    strlcpy(buffer_small, helloworld, sizeof(buffer_small));

    /* TODO: this condition shouldn't be mandatory :( */
    if (!is_valid_cstring((char*)helloworld, HELLO_WORLD_LEN)) {
        return 0;
    }
    /*@ assert valid_cstring((char*)helloworld); */
    /*@ assert strlen((char*)helloworld) == HELLO_WORLD_LEN; */
    /*@ assert HELLO_WORLD_LEN < sizeof(buffer_big); */
    /*@ assert strlen((char*)helloworld) < sizeof(buffer_big); */
    strlcpy(buffer_big, helloworld, sizeof(buffer_big));
    return 0;
}
