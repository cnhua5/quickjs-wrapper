// qjs_syscall_map.h

enum {
    OP_GETPID = 1,
    OP_OPENAT = 2,
    OP_READ   = 3,
    OP_WRITE  = 4,
    OP_CLOSE  = 5,
};

struct syscall_map {
    int opcode;
    int nr;
};

static const struct syscall_map g_syscall_map[] = {
        { OP_GETPID,  __NR_getpid },
        { OP_OPENAT,  __NR_openat },
        { OP_READ,    __NR_read },
        { OP_WRITE,   __NR_write },
        { OP_CLOSE,   __NR_close },
};

static int opcode_to_nr(int opcode) {
    for (int i = 0; i < sizeof(g_syscall_map)/sizeof(g_syscall_map[0]); i++) {
        if (g_syscall_map[i].opcode == opcode) {
            return g_syscall_map[i].nr;
        }
    }
    return -1;
}
