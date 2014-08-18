/**
 * Print Hello world according to the command line.
 */
#include <stdio.h>
#include <string.h>

#ifdef __FRAMAC__
/**
 * Frama-C 20140301 doesn't assume anything about main arguments.
 * Let's build an initial stack which is writable, with dummy parameters.
 * Another way of doing this may consist in declaring extern functions which
 * give argv and ensure a bunch of statements.
 */
static char main_argv0[] = "this-program";
static char main_argv1[] = "-h";
static char main_argv2[] = "-b";
static char *main_argv[] = {
    (char*)main_argv0,
    (char*)main_argv1,
    (char*)main_argv2,
    NULL};
/* Use a pointer instead of a constant integet to be able to use this value in axioms */
static const int main_argc[1] = {(sizeof(main_argv) / sizeof(main_argv[0])) - 1};

/*@ axiomatic MainArgs {
  @ axiom argc_positive:
  @     0 <= *main_argc;
  @
  @ axiom argv_valid1:
  @     \valid(main_argv + (0 .. *main_argc));
  @
  @ axiom argv_valid2:
  @     \forall integer i; 0 <= i < *main_argc ==> valid_string(main_argv[i]);
  @
  @ axiom argv_lastnul:
  @     main_argv[*main_argc] == \null;
  @
  @ axiom separated_argv_stdout1:
  @     \separated(__fc_stdout, main_argv + (0 .. *main_argc));
  @
  @ axiom separated_argv_stdout2:
  @     \forall integer i; 0 <= i < *main_argc ==>
  @         \separated(__fc_stdout, main_argv[i] + (0 .. strlen(main_argv[i])));
  @ }
  @*/

int real_main(int argc, char **argv);

/*@ assigns *__fc_stdout;
  @ ensures \result == 0;
  @*/
int main(void)
{
    return real_main(*main_argc, (char**)main_argv);
}
#define main real_main
#endif

/*@ requires 0 <= argc;
  @ requires \valid(argv + (0 .. argc));
  @ requires argv[argc] == \null;
  @ requires \forall integer i; 0 <= i < argc ==> valid_string(argv[i]);
  @ requires \separated(__fc_stdout, argv + (0 .. argc));
  @ requires \forall integer i; 0 <= i < argc ==>
  @     \separated(__fc_stdout, argv[i] + (0 .. strlen(argv[i])));
  @ assigns *__fc_stdout;
  @ ensures \result == 0;
  @*/
int main(int argc, char **argv)
{
    int i;
    /*@ ghost entry:*/
    /*@ loop invariant 0 <= i <= argc;
      @ loop invariant \forall integer j; 0 <= j < argc ==> valid_string(argv[j]);
      @ loop assigns i, *__fc_stdout;
      @ loop variant argc - i;
      @*/
    for (i = 0; i < argc; i++) {
        /*@ assert 0 <= i < argc; */
        char *a = argv[i];
        /*@ assert valid_string(a); */
        /* Don't use constant strings and strcmp because in Frama-C 20140301,
         * strcmp requires \valid_string on its parameters, which verify RW
         * access, and constant strings are not writable.
         */
        if (a[0] == '-' && a[1] == 'h' && a[2] == '\0') {
            printf("Hello, world!\n");
        } else if (a[0] == '-' && a[1] == 'b' && a[2] == '\0') {
            printf("Bye.\n");
            return 0;
        }
    }
    return 0;
}
