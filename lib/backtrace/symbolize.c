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

#include <lib/backtrace/symbolize.h>
#include <trace.h>

#include "elf_sym.h"

#define LOCAL_TRACE 0

#undef ELF_64BIT
#if !IS_64BIT || USER_32BIT
#define ELF_64BIT 0
#else
#define ELF_64BIT 1
#endif

#if ELF_64BIT
#define ELF_SHDR Elf64_Shdr
#define ELF_EHDR Elf64_Ehdr
#define ELF_SYM Elf64_Sym
#else
#define ELF_SHDR Elf32_Shdr
#define ELF_EHDR Elf32_Ehdr
#define ELF_SYM Elf32_Sym
#endif

int trusty_app_symbolize(struct trusty_app* app,
                         uintptr_t pc,
                         struct pc_symbol_info* info) {
    if (!app) {
        goto out_no_symbol;
    }
    /* Adjust pc to be relative to app image */
    __builtin_sub_overflow(pc, app->load_bias, &pc);

    struct trusty_app_img* app_img = app->app_img;
    ELF_EHDR* ehdr = (ELF_EHDR*)app_img->img_start;
    ELF_SHDR* shdr = (ELF_SHDR*)((uintptr_t)ehdr + ehdr->e_shoff);

    ELF_SHDR* symtab_shdr = NULL;
    ELF_SHDR* strtab_shdr = NULL;

    /* Find section headers for .symtab and .strtab */
    for (size_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            symtab_shdr = shdr + i;
        }
        if (shdr[i].sh_type == SHT_STRTAB) {
            strtab_shdr = shdr + i;
        }
    }

    /* Handle the case when app is not built with .symtab or .strtab */
    if (!symtab_shdr || !strtab_shdr) {
        LTRACEF("App built without symbol table\n");
        goto out_no_symbol;
    }

    uintptr_t symtab_start =
            (uintptr_t)(app_img->img_start + symtab_shdr->sh_offset);
    uintptr_t strtab_start =
            (uintptr_t)(app_img->img_start + strtab_shdr->sh_offset);

    /* Find closest symbol preceding pc */
    uintptr_t curr = symtab_start;
    info->offset = ULONG_MAX;
    while (curr < symtab_start + symtab_shdr->sh_size) {
        curr += symtab_shdr->sh_entsize;
        ELF_SYM* symtab_entry = (ELF_SYM*)curr;
        /* Symbol must have some type defined */
        if (symtab_entry->st_info == 0) {
            continue;
        }

        uintptr_t func_start = symtab_entry->st_value;
        if (func_start <= pc && info->offset > pc - func_start) {
            info->symbol = (const char*)(strtab_start + symtab_entry->st_name);
            info->offset = pc - func_start;
            info->size = symtab_entry->st_size;
        }
    }

    if (info->offset == ULONG_MAX) {
        goto out_no_symbol;
    }
    return NO_ERROR;

out_no_symbol:
    info->symbol = NULL;
    info->offset = 0;
    info->size = 0;
    return ERR_NOT_FOUND;
}
