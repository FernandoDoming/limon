#include <sys/user.h>
#include <sys/wait.h>
#include "tracy.h"

void spawn_tracee_process(void* cmd);
int hook_syscall(struct tracy_event* e);
void print_syscall(struct tracy_event* e);

#ifdef X64

#endif

#ifdef ARM32

#endif

#ifdef ARM64

#endif