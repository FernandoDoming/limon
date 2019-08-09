#include <sys/user.h>
#include <sys/wait.h>

void spawn_tracee_process(void* cmd);
void* ptrace_syscall_mon_loop(void* optarg);

#ifdef X64
void x64_ptrace_loop(pid_t child_pid);
void print_syscall_x64(struct user_regs_struct* regs);
#endif

#ifdef ARM32
void arm32_ptrace_loop(pid_t child_pid);
#endif

#ifdef ARM64
void arm64_ptrace_loop(pid_t child_pid);
#endif