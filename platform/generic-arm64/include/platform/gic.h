/*
 * Copyright (c) 2015 Google Inc. All rights reserved
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
#ifndef __PLATFORM_GIC_H
#define __PLATFORM_GIC_H

#define MAX_INT 1020
#if ARCH_ARM64
#define GIC_BASE_VIRT 0xffffffffffe20000
#else
#define GIC_BASE_VIRT 0xffe20000
#endif
#define GICBASE(b) (GIC_BASE_VIRT)

#if GIC_VERSION <= 2
#define GIC_GAP (0x1f000)
#define GICC_SIZE (0x1000)
#define GICD_SIZE (0x1000)
#else
#define GIC_GAP (0x10000)
#define GICC_SIZE (0x10000)
#define GICD_SIZE (0x10000)
#if GIC_VERSION < 4
#define GICR_SIZE (0x20000 * 8)
#else
#define GICR_SIZE (0x30000 * 8)
#endif
#endif

#define GICC_OFFSET (0x0000)
#define GICD_OFFSET (GICC_OFFSET + GICC_SIZE + GIC_GAP)
#define GICR_OFFSET (GICD_OFFSET + GICD_SIZE + GIC_GAP)

#define GICC_BASE_VIRT (GIC_BASE_VIRT + GICC_OFFSET)
#define GICD_BASE_VIRT (GIC_BASE_VIRT + GICD_OFFSET)
#define GICR_BASE_VIRT (GIC_BASE_VIRT + GICR_OFFSET)

#endif
