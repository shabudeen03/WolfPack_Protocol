#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/wait.h>
#include <assert.h>
#include "criterion/criterion.h"

#include "wolfpack.h"

#define TEST_INPUT_DIR "tests.in"
#define TEST_OUTPUT_DIR "tests.out"
#define TEST_TIMEOUT 5 

int run_using_system(char *test_name);
int run_using_system_no_valgrind(char *test_name);
void expect_normal_exit(int status);
void expect_error_exit(int status);
void expect_no_valgrind_errors(int status);
void expect_outfile_matches(char *name);
void report_return_value(int return_act, int return_exp);
void report_message(char *actual, char *expected);
void report_packets(unsigned char *actual[], char *expected[], unsigned int *packet_lens_exp, unsigned int num_expected);