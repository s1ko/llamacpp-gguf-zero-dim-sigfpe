#include <stdio.h>

#include "ggml.h"
#include "gguf.h"

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s file.gguf\n", argv[0]);
        return 2;
    }
    struct gguf_init_params params = { .no_alloc = true, .ctx = NULL };
    struct gguf_context * ctx = gguf_init_from_file(argv[1], params);
    if (ctx == NULL) {
        printf("gguf_init_from_file: rejected the file (returned NULL)\n");
        return 1;
    }
    printf("gguf_init_from_file: accepted, %lld tensors\n", (long long) gguf_get_n_tensors(ctx));
    gguf_free(ctx);
    return 0;
}
