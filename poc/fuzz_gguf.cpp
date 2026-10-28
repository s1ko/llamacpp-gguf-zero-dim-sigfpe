#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

#include "gguf.h"
#include "ggml.h"

static thread_local jmp_buf g_jmp;
static thread_local volatile int g_jmp_set = 0;

static void abort_cb(const char *) {
    if (g_jmp_set) {
        g_jmp_set = 0;
        longjmp(g_jmp, 1);
    }
}

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    ggml_set_abort_callback(abort_cb);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    FILE *f = fmemopen((void *)data, size, "rb");
    if (!f) return 0;

    struct ggml_context *ggml_ctx = nullptr;
    struct gguf_init_params params_alloc = {
        /*.no_alloc = */ false,
        /*.ctx      = */ &ggml_ctx,
    };

    g_jmp_set = 1;
    if (setjmp(g_jmp) == 0) {
        struct gguf_context *ctx = gguf_init_from_file_ptr(f, params_alloc);
        if (ctx) gguf_free(ctx);
        if (ggml_ctx) ggml_free(ggml_ctx);
    }
    g_jmp_set = 0;

    fclose(f);

    FILE *f2 = fmemopen((void *)data, size, "rb");
    if (!f2) return 0;

    struct gguf_init_params params_noalloc = {
        /*.no_alloc = */ true,
        /*.ctx      = */ nullptr,
    };

    g_jmp_set = 1;
    if (setjmp(g_jmp) == 0) {
        struct gguf_context *ctx = gguf_init_from_file_ptr(f2, params_noalloc);
        if (ctx) gguf_free(ctx);
    }
    g_jmp_set = 0;

    fclose(f2);

    return 0;
}
