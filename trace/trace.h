#include <sys/user.h>
#include <sys/wait.h>
#include "tracy.h"

void spawn_tracee_process(void* cmd);
int hook_syscall(struct tracy_event* e);
void print_syscall(struct tracy_event* e);

#ifdef X64

#endif

#ifdef ARM32
void arm32_ptrace_loop(pid_t pid);
#endif

#ifdef ARM64
void arm64_ptrace_loop(pid_t pid);
#endif