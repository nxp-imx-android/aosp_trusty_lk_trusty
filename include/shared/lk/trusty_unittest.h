/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once

#include <lk/compiler.h>
#include <lk/list.h>
#include <stdbool.h>
#include <string.h>

__BEGIN_CDECLS

/*
 * Test functions can be defined with:
 * TEST(SuiteName, TestName) {
 *   ... test body ...
 * }
 * or with:
 * TEST_F(SuiteName, TestName) {
 *   ... test body ...
 * }
 *
 * Use EXPECT_<op> or ASSERT_<op> directly in test functions or from nested
 * functions to check test conditions. Where <op> can be:
 *   EQ for ==
 *   NE for !=
 *   LT for <
 *   LE for <=
 *   GT for >
 *   GE for >=
 *
 * The test functions follows this pattern:
 *   <EXPECT|ASSERT>_<op>(val1, val2 [, format, ...])
 * If val1 <op> val2 is not true, then both values will be printed and a test
 * failure will be recorded. For ASSERT_<op> it will also jump to a test_abort
 * label in the calling function.
 *
 * Call RUN_ALL_TESTS() to run all tests defined by TEST (or
 * RUN_ALL_SUITE_TESTS("SuiteName") to only run tests with the specified
 * SuiteName). RUN_ALL_TESTS and RUN_ALL_SUITE_TESTS return true if all the
 * tests passed.
 *
 * If test functions are defined with TEST_F, it expects the type <SuiteName>_t
 * and <SuiteName>_SetUp and <SuiteName>_TearDown functions. A pointer to
 * a <SuiteName>_t variable will be passed to the test function as _state.
 *
 * TEST_FIXTURE_ALIAS(NewSuiteName, OldSuiteName) can be used to use the test
 * fixture defined for OldSuiteName with NewSuiteName.
 *
 * TEST_INIT, TEST_END and TESTS_PASSED are provided for backwards
 * compatibility.
 */

#ifndef trusty_unittest_printf
#error trusty_unittest_printf must be defined
#endif

/**
 * struct test_context - struct representing the state of a test run.
 * @tests_total:    Number of conditions checked
 * @tests_failed:   Number of conditions failed
 * @test_name:      Name of current test case
 * @all_ok:         State of current test case
 */
struct test_context {
    unsigned int tests_total;
    unsigned int tests_failed;
    const char* test_name;
    bool all_ok;
};

/**
 * struct test_list_node - node to hold test function in list of tests
 * @node:       List node
 * @suite:      Name of test suite (optionally used for filtering)
 * @func:       Test function
 */

struct test_list_node {
    struct list_node node;
    const char* suite;
    void (*func)(void);
};

static struct test_context _test_context;

/*
 * List of tests. Tests are added by a __attribute__((constructor)) function
 * per test defined by the TEST macro.
 */
static struct list_node _test_list = LIST_INITIAL_VALUE(_test_list);

static inline void TEST_INIT(void) {
    _test_context.tests_total = 0;
    _test_context.tests_failed = 0;
}

static inline bool TESTS_PASSED(void) {
    return _test_context.tests_failed == 0;
}

static inline void TEST_BEGIN_FUNC(const char* name) {
    _test_context.test_name = name;
    _test_context.all_ok = true;
    _test_context.tests_total++;
    trusty_unittest_printf("[ RUN      ] %s\n", _test_context.test_name);
}

#define TEST_BEGIN(name) \
    { TEST_BEGIN_FUNC(name); }

static inline void TEST_END_FUNC(void) {
    if (_test_context.all_ok) {
        trusty_unittest_printf("[       OK ] %s\n", _test_context.test_name);
    } else {
        trusty_unittest_printf("[  FAILED  ] %s\n", _test_context.test_name);
    }
    _test_context.test_name = NULL;
}

#define TEST_END \
    { TEST_END_FUNC(); }

#define STRINGIFY(x) #x

#define TEST_FIXTURE_ALIAS(new_suite_name, old_suite_name)              \
    typedef old_suite_name##_t new_suite_name##_t;                      \
                                                                        \
    static void new_suite_name##_SetUp(new_suite_name##_t* _state) {    \
        old_suite_name##_SetUp(_state);                                 \
    }                                                                   \
    static void new_suite_name##_TearDown(new_suite_name##_t* _state) { \
        old_suite_name##_TearDown(_state);                              \
    }

#define TEST_INTERNAL(suite_name, test_name, pre, post, arg, argp)           \
    static void suite_name##_##test_name##_inner argp;                       \
                                                                             \
    static void suite_name##_##test_name(void) {                             \
        TEST_BEGIN_FUNC(STRINGIFY(suite_name##_##test_name));                \
        {                                                                    \
            pre;                                                             \
            suite_name##_##test_name##_inner arg;                            \
            post;                                                            \
        }                                                                    \
        TEST_END_FUNC();                                                     \
    }                                                                        \
                                                                             \
    static struct test_list_node suite_name##_##test_name##_node = {         \
            .node = LIST_INITIAL_CLEARED_VALUE,                              \
            .suite = #suite_name,                                            \
            .func = suite_name##_##test_name,                                \
    };                                                                       \
                                                                             \
    __attribute__((constructor)) void suite_name##_##test_name##_add(void) { \
        list_add_tail(&_test_list, &suite_name##_##test_name##_node.node);   \
    }                                                                        \
                                                                             \
    static void suite_name##_##test_name##_inner argp

#define TEST(suite_name, test_name) \
    TEST_INTERNAL(suite_name, test_name, , , (), (void))

#define TEST_F_CUSTOM_ARGS(suite_name, test_name, arg, argp)                  \
    TEST_INTERNAL(suite_name, test_name, suite_name##_t state;                \
                  suite_name##_SetUp(&state);, suite_name##_TearDown(&state); \
                  , arg, argp)

#define TEST_F(suite_name, test_name)                   \
    TEST_F_CUSTOM_ARGS(suite_name, test_name, (&state), \
                       (suite_name##_t * _state))

static inline bool RUN_ALL_SUITE_TESTS(const char* suite) {
    struct test_list_node* entry;
    TEST_INIT();
    list_for_every_entry(&_test_list, entry, struct test_list_node, node) {
        if (!suite || !strcmp(suite, entry->suite)) {
            entry->func();
        }
    }

    trusty_unittest_printf("[==========] %d tests ran.\n",
                           _test_context.tests_total);
    if (_test_context.tests_total != _test_context.tests_failed) {
        trusty_unittest_printf(
                "[  PASSED  ] %d tests.\n",
                _test_context.tests_total - _test_context.tests_failed);
    }
    if (_test_context.tests_failed) {
        trusty_unittest_printf("[  FAILED  ] %d tests.\n",
                               _test_context.tests_failed);
    }
    return TESTS_PASSED();
}

static inline bool RUN_ALL_TESTS(void) {
    return RUN_ALL_SUITE_TESTS(NULL);
}

#define ASSERT_EXPECT_TEST(op, fail_action, val1, val2, extra_msg...)        \
    {                                                                        \
        __typeof__(val2) _val1 = val1;                                       \
        __typeof__(val2) _val2 = val2;                                       \
        if (!(_val1 op _val2)) {                                             \
            trusty_unittest_printf("%s: @ %s:%d\n", _test_context.test_name, \
                                   __FILE__, __LINE__);                      \
            trusty_unittest_printf("  expected: " #val1 " (%ld) " #op        \
                                   " " #val2 " (%ld)\n",                     \
                                   (long)_val1, (long)_val2);                \
            trusty_unittest_printf("  " extra_msg);                          \
            trusty_unittest_printf("\n");                                    \
            if (_test_context.all_ok) {                                      \
                _test_context.all_ok = false;                                \
                _test_context.tests_failed++;                                \
            }                                                                \
            fail_action                                                      \
        }                                                                    \
    }

static inline bool HasFailure(void) {
    return !_test_context.all_ok;
}

#define ASSERT_ALL_OK()  \
    if (HasFailure()) {  \
        goto test_abort; \
    }

#define EXPECT_TEST(op, args...) ASSERT_EXPECT_TEST(op, , args)
#define EXPECT_EQ(args...) EXPECT_TEST(==, args)
#define EXPECT_NE(args...) EXPECT_TEST(!=, args)
#define EXPECT_LT(args...) EXPECT_TEST(<, args)
#define EXPECT_LE(args...) EXPECT_TEST(<=, args)
#define EXPECT_GT(args...) EXPECT_TEST(>, args)
#define EXPECT_GE(args...) EXPECT_TEST(>=, args)

#define ASSERT_TEST(op, args...) ASSERT_EXPECT_TEST(op, goto test_abort;, args)
#define ASSERT_EQ(args...) ASSERT_TEST(==, args)
#define ASSERT_NE(args...) ASSERT_TEST(!=, args)
#define ASSERT_LT(args...) ASSERT_TEST(<, args)
#define ASSERT_LE(args...) ASSERT_TEST(<=, args)
#define ASSERT_GT(args...) ASSERT_TEST(>, args)
#define ASSERT_GE(args...) ASSERT_TEST(>=, args)

__END_CDECLS
