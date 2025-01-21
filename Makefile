CPU := $(shell uname -p)
ifeq ($(CPU),arm)
export LD_LIBRARY_PATH=/opt/homebrew/lib/:$LD_LIBRARY_PATH
INCD = -I /opt/homebrew/include/
LIBD = -L /opt/homebrew/lib/
endif

CC := gcc
SRCD := src
TSTD := tests
AUXD := tests_aux
BLDD := build
BIND := bin
INCD += -I include

ALL_SRCF := $(shell find $(SRCD) -type f -name '*.c')
ALL_OBJF := $(patsubst $(SRCD)/%,$(BLDD)/%,$(ALL_SRCF:.c=.o))
FUNC_FILES := $(filter-out build/main.o, $(ALL_OBJF))
TEST_SRC := $(shell find $(TSTD) -type f -name '*.c')
TEST_OBJ := $(patsubst $(TSTD)/%,$(BLDD)/%,$(TEST_SRC:.c=.o))
AUX_SRC := $(shell find $(AUXD) -type f -name '*.c')

TEST := unit_tests

AUX_OBJS := $(patsubst $(AUXD)/%,$(BLDD)/%,$(AUX_SRC:.c=.o))
AUX_PGMS := $(patsubst $(AUXD)/%,$(BIND)/%,$(AUX_SRC:.c=))

CFLAGS := -Wall -Wextra -Wshadow -Wdouble-promotion -Wformat=2 -Wundef -pedantic
GCOV := -fprofile-arcs -ftest-coverage
DFLAGS := -g -DDEBUG
PRINT_STATEMENTS := -DERROR -DSUCCESS -DWARN -DINFO

STD := -std=gnu11
TEST_LIB := -lcriterion
LIBS := -lm

CFLAGS += $(STD)
CFLAGS += $(GCOV)
CFLAGS += $(DFLAGS)

TEST_RESULTS := "test_results.json"
OCLINT_REPORT := "oclint_report.html"
GCOV_REPORT := "wolfpack.c.gcov"

MAKEFLAGS := -j

all: setup $(BIND)/$(TEST) $(AUX_PGMS) $(ALL_OBJF)

debug: CFLAGS += $(DFLAGS) $(PRINT_STATEMENTS) 
debug: all

setup: $(BIND) $(BLDD)
$(BIND):
	mkdir -p $(BIND)
$(BLDD):
	mkdir -p $(BLDD)

$(BIND)/$(TEST): $(FUNC_FILES) $(TEST_OBJ)
	$(CC) $(CFLAGS) $(INCD) $(FUNC_FILES) $(TEST_OBJ) $(TEST_LIB) $(LIBD) -o $@ $(LIBS)

$(AUX_PGMS): % : $(AUX_OBJS) $(FUNC_FILES) 
	$(CC) $(GCOV) $(BLDD)/$(@F).o $(FUNC_FILES) -o $@ $(LIBS)

$(BLDD)/%.o: $(AUXD)/%.c 
	$(CC) $(CFLAGS) $(INCD) -c -o $@ $<

$(BLDD)/%.o: $(TSTD)/%.c
	$(CC) $(CFLAGS) $(INCD) -c -o $@ $<

$(BLDD)/%.o: $(SRCD)/%.c 
	$(CC) $(CFLAGS) $(INCD) -c -o $@ $<

test: 
	@rm -fr $(TSTD).out
	@mkdir -p $(TSTD).out
	@$(BIND)/$(TEST) --full-stats --verbose --json=$(TEST_RESULTS) -j1

gcov:
	@gcov wolfpack.o -o build -s src > /dev/null 2>&1
	@echo Generated unit test coverage report for wolfpack.c. See $(GCOV_REPORT)

clean:
	rm -fr $(BLDD) $(BIND) $(TSTD).out $(AUXD)/*.o *.out $(OCLINT_REPORT) $(GCOV_REPORT) $(TEST_RESULTS)

.PHONY: all clean debug criterion setup test