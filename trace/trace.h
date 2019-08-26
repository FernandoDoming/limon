#pragma once

#include <sys/user.h>
#include <sys/wait.h>
#include "tracy.h"
#include "macro.h"

TAILQ_HEAD(argv_q, str_list_entry) argv_head;

void spawn_tracee_process(void* cmd);
void print_syscall(struct tracy_event* e);

size_t read_remote_string_array(
    struct tracy_event* e,
    char** rtable,
    struct argv_q* argv_head
);

int hook_syscall(struct tracy_event* e);
int hook_execve(struct tracy_event* e);
