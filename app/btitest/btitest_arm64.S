/*
 * Copyright (c) 2022, Google Inc. All rights reserved
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

#include <asm.h>
#include <arch/asm_macros.h>
#include <err.h>

.section .text

/* Fault handler to return where BTI calls fail.
 * On return from the caught Branch Target exception, PSTATE.BTYPE will still
 * be set according to the last branch taken.  Therefore we need to land on a
 * BTI jc to be compatible with all callers - and avoid another immediate
 * Branch Target exception.
 */
.Lbtitest_callee_fault:
    bti jc
    mov x0, #ERR_FAULT
    ret

/**
 * int btitest_blr(int (*func)(void)) - Use blr to call the passed function
 *
 * Returns The called function's return value
 */
FUNCTION(btitest_blr)
    push lr, xzr
    blr x0
    pop lr, xzr
    ret

/**
 * int btitest_br(int (*func)(void)) - Use br to call the passed function
 *                                     via the x0 register
 *
 * Returns The called function's return value
 */

FUNCTION(btitest_br)
    br x0

/**
 * int btitest_br_x16(int (*func)(void)) - Use br to call the passed function
 *                                         via the x16 register
 *
 * Returns The called function's return value
 */

FUNCTION(btitest_br_x16)
    mov x16, x0
    br x16

/**
 * int btitest_br_x17(int (*func)(void)) - Use br to call the passed function
 *                                         via the x17 register
 *
 * Returns The called function's return value
 */

FUNCTION(btitest_br_x17)
    mov x17, x0
    br x17

/**
 * int btitest_callee_nop(void) - Function with nop instruction
 *
 * Returns ERR_FAULT if the BTI check fails.
 * Return 0 if the BTI check passes.
 */
FUNCTION(btitest_callee_nop)
    set_fault_handler .Lbtitest_callee_fault
    nop
    mov	x0, #0
    ret

/**
 * int btitest_callee_bti(void) - Function with bti instruction
 *
 * Returns ERR_FAULT if the BTI check fails.
 * Return 0 if the BTI check passes.
 */
FUNCTION(btitest_callee_bti)
    set_fault_handler .Lbtitest_callee_fault
    bti
    mov	x0, #0
    ret

/**
 * int btitest_callee_bti_c(void) - Function with bti c instruction
 *
 * Returns ERR_FAULT if the BTI check fails.
 * Return 0 if the BTI check passes.
 */
FUNCTION(btitest_callee_bti_c)
    set_fault_handler .Lbtitest_callee_fault
    bti c
    mov	x0, #0
    ret

/**
 * int btitest_callee_bti_j(void) - Function with bti j instruction
 *
 * Returns ERR_FAULT if the BTI check fails.
 * Return 0 if the BTI check passes.
 */
FUNCTION(btitest_callee_bti_j)
    set_fault_handler .Lbtitest_callee_fault
    bti j
    mov	x0, #0
    ret

/**
 * int btitest_callee_bti_jc(void) - Function with bti jc instruction
 *
 * Returns ERR_FAULT if the BTI check fails.
 * Return 0 if the BTI check passes.
 */
FUNCTION(btitest_callee_bti_jc)
    set_fault_handler .Lbtitest_callee_fault
    bti jc
    mov	x0, #0
    ret
