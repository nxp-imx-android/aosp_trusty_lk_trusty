#include <malloc.h>

#include <lib/unittest/unittest.h>

static uintptr_t expected_malloc_alignment(size) {
    /* TODO use ffs? */
    if (size >= 16) {
        return sizeof(void*) * 2;
    } else if (size >= 8) {
        return 8;
    } else if (size >= 4) {
        return 4;
    } else if (size >= 2) {
        return 2;
    } else {
        return 1;
    }
}

TEST(memorytest, malloc_alignment) {
    for (int size = 2; size < 256; size++) {
        const uintptr_t alignment_mask = expected_malloc_alignment(size) - 1;
        void* ptr1 = malloc(size);
        void* ptr2 = malloc(size / 2); /* Try to shake up the alignment. */
        void* ptr3 = malloc(size);

        ASSERT_EQ(0, (uintptr_t)ptr1 & alignment_mask, "size %d / align %ld\n",
                  size, alignment_mask + 1);
        ASSERT_EQ(0, (uintptr_t)ptr3 & alignment_mask, "size %d / align %ld\n",
                  size, alignment_mask + 1);

        free(ptr3);
        free(ptr2);
        free(ptr1);
    }
test_abort:;
}

PORT_TEST(memorytest, "com.android.kernel.memorytest");
