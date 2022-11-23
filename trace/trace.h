#pragma once

#include <sys/user.h>
#include <sys/wait.h>
#include "tracy.h"
#include "macro.h"
#include "types.h"

struct tracy* init_tracing(pid_t tracee_pid);
void free_tracing(struct tracy* tracy);

void spawn_tracee_process(void* cmd);
void add_traced_proc(pid_t pid, pid_t ppid);
bool is_traced_proc(pid_t pid);

void print_syscall(struct tracy_event* e);
long get_tracy_abi_for_proc(pid_t pid);

size_t read_remote_string(
    struct tracy_event* e,
    char* rstring,
    char* buffer,
    size_t buflen
);

int signal_hook(struct tracy_event *e);
int hook_syscall(struct tracy_event* e);
int hook_ptrace(struct tracy_event* e);
int hook_clone(struct tracy_event* e);
int hook_open(struct tracy_event* e);
int hook_openat(struct tracy_event* e);
int hook_write(struct tracy_event* e);
int hook_execve(struct tracy_event* e);
