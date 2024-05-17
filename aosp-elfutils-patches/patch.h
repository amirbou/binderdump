// These functions are required to exist by `configure`, but they are not used when building only libelf.

static inline char argp_parse(void) {
    return 0;
}

static inline char _obstack_free(void) {
    return 0;
}