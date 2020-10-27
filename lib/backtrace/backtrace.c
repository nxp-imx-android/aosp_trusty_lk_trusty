/*
 * Copyright (c) 2020 Google Inc. All rights reserved
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

#include <assert.h>
#include <inttypes.h>
#include <lib/backtrace/backtrace.h>
#include <lib/backtrace/symbolize.h>
#include <lib/trusty/trusty_app.h>

#if IS_64BIT
#define PRI0xPTR "016" PRIxPTR
#else
#define PRI0xPTR "08" PRIxPTR
#endif

static void print_function_info(struct stack_frame* frame,
                                uintptr_t load_bias,
                                struct pc_symbol_info* info) {
    uintptr_t pc_offset;
    uintptr_t pc = frame->ret_addr;
    __builtin_sub_overflow(pc, load_bias, &pc_offset);

    printf("0x%" PRI0xPTR ": 0x%" PRI0xPTR "/0x%" PRI0xPTR, frame->fp, pc,
           pc_offset);

    if (info) {
        printf(" %s+0x%lx/0x%lx\n", info->symbol, info->offset, info->size);
    } else {
        printf("\n");
    }
}

static void dump_user_function(struct trusty_app* app,
                               struct stack_frame* frame) {
    uintptr_t load_bias = app ? app->load_bias : 0;
    struct pc_symbol_info info;
    int rc = trusty_app_symbolize(app, frame->ret_addr, &info);
    if (rc == NO_ERROR) {
        print_function_info(frame, load_bias, &info);
    } else {
        print_function_info(frame, load_bias, NULL);
    }
}

static void dump_kernel_function(struct stack_frame* frame) {
    /* TODO(b/149918767): kernel instruction address symbolization */
    print_function_info(frame, 0 /* load_bias */, NULL);
}

/**
 * dump_function() - dump symbol info about function containing pc
 * @thread: thread containing the instruction
 * @frame: instruction address of the function being dumped and next frame ptr
 */
static void dump_function(thread_t* thread, struct stack_frame* frame) {
    if (is_user_address(frame->ret_addr)) {
        dump_user_function(trusty_thread_get(thread)->app, frame);
    } else if (is_kernel_address(frame->ret_addr)) {
        dump_kernel_function(frame);
    }
}

static bool is_on_user_stack(struct thread* _thread, uintptr_t addr) {
    uintptr_t stack_end;
    uintptr_t stack_bottom;
    struct trusty_thread* thread = trusty_thread_get(_thread);

    if (!thread) {
        return false;
    }

    stack_end = thread->stack_start;
    if (__builtin_sub_overflow(stack_end, thread->stack_size, &stack_bottom)) {
        return false;
    }

    return stack_bottom <= addr && addr < stack_end;
}

static bool is_on_kernel_stack(struct thread* thread, uintptr_t addr) {
    uintptr_t stack_bottom;
    uintptr_t stack_end;

    stack_bottom = (uintptr_t)thread->stack;
    if (__builtin_add_overflow(stack_bottom, thread->stack_size, &stack_end)) {
        return false;
    }

    return stack_bottom <= addr && addr < stack_end;
}

/**
 * is_on_stack() - check if address is on the stack
 * @thread: thread that owns the stack
 * @addr: address being checked
 * @user: true if we need to check against user stack, false if kernel stack
 *
 * Return: true if @addr is on the stack, false otherwise
 */
static bool is_on_stack(struct thread* thread, uintptr_t addr, bool user) {
    if (user) {
        return is_on_user_stack(thread, addr);
    } else {
        return is_on_kernel_stack(thread, addr);
    }
}

static inline bool is_trace_monotonic(uintptr_t prev_fp, uintptr_t next_fp) {
    return stack_direction ? next_fp < prev_fp : next_fp > prev_fp;
}

/**
 * dump_monotonic_backtrace() - dump backtrace while only moving up the stack
 * @thread: thread being backtraced
 * @frame: starting frame, used to iterate through frames in-place
 * @user: true if we're traversing a user stack, false if kernel stack
 *
 * Return: state of @frame
 */
static int dump_monotonic_backtrace(struct thread* thread,
                                    struct stack_frame* frame,
                                    bool user) {
    uintptr_t prev_fp = 0;
    int frame_state = FRAME_OK;
    while (frame_state == FRAME_OK) {
        prev_fp = frame->fp;
        frame_state = step_frame(frame, user);
        dump_function(thread, frame);

        if (is_on_stack(thread, frame->fp, !user)) {
            /* Transistion to a different stack */
            return FRAME_OK;
        }
        if (is_zero_frame(frame)) {
            return FRAME_ZERO;
        }
        /* Validate that FP actually points to the stack */
        if (!is_on_stack(thread, frame->fp, user)) {
            return FRAME_CORRUPT;
        }
        /* Stack should only move in one direction */
        if (prev_fp && !is_trace_monotonic(prev_fp, frame->fp)) {
            return FRAME_NON_MONOTONIC;
        }
    }
    return frame_state;
}

static void dump_backtrace_etc(struct thread* thread,
                               struct stack_frame* frame) {
    /*
     * dump_backtrace_*() functions can only be called from kernel space.
     * Expect the first frame to be in kernel address space
     */
    assert(is_kernel_address(frame->fp));
    int frame_state = dump_monotonic_backtrace(thread, frame, false);

    if (frame_state == FRAME_OK && is_user_address(frame->fp)) {
        frame_state = dump_monotonic_backtrace(thread, frame, true);
    }

    switch (frame_state) {
    case FRAME_ZERO:
        /* Backtrace is expected to terminate with a zero frame */
        break;
    case FRAME_NON_MONOTONIC:
        printf("Stack frame moved in wrong direction! "
               "fp: 0x%lx, ret_addr: 0x%lx\n",
               frame->fp, frame->ret_addr);
        break;
    default:
        printf("Corrupt stack frame! "
               "fp: 0x%lx, ret_addr: 0x%lx\n",
               frame->fp, frame->ret_addr);
    }
}

void dump_thread_backtrace(struct thread* thread) {
    /*
     * TODO(b/149918767): Support backtracing for non-current threads. We need
     * operations on trusty_thread and trusty_app to be thread-safe first.
     */
    assert(thread == get_current_thread());

    struct stack_frame frame = {0};
    get_current_frame(&frame);

    printf("\nBacktrace: \n");
    dump_backtrace_etc(thread, &frame);
}
