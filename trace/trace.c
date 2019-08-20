#include <pthread.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <errno.h>

#include "trace.h"
#include "macro.h"
#include "fsmon.h"
#include "util.h"

extern FILE* outfd;
extern FileMonitor fm;
extern bool firstnode;

/*
 * Changes executable image to another one provided by cmd arg 
 * and trace it with ptrace. Should be run by a child proc
 */
void spawn_tracee_process(void* cmd)
{
    if (cmd == NULL) return;

    printf("Executing command %s\n", cmd);
	if (execl(cmd, cmd, NULL) == -1) {
		FATAL("ERROR trying to spawn %s", (char*) cmd);
	}
}

int hook_syscall(struct tracy_event* e) {
    print_syscall(e);
    return TRACY_HOOK_CONTINUE;
}

void print_syscall(struct tracy_event* e)
{
    /* Print a representation of the system call */
    if (fm.json || fm.jsonStream) {
        fprintf(
            outfd,
            "%s{\"event_type\":\"syscall\","
            "\"pid\":%d,"
            "\"syscall_name\":\"%s\","
            "\"syscall_n\":%ld,"
            "\"a0\":%ld,"
            "\"a1\":%ld,"
            "\"a2\":%ld,"
            "\"a3\":%ld,"
            "\"a4\":%ld,"
            "\"a5\":%ld"
            "}\n",
            (fm.jsonStream || firstnode) ? "" : ",",
            e->child->pid,
            get_syscall_name_abi(e->syscall_num, TRACY_ABI_NATIVE),
            e->syscall_num,
            (long) e->args.a0, (long) e->args.a1, (long) e->args.a2,
            (long) e->args.a3, (long) e->args.a4, (long) e->args.a5
        );
    }
    else {
        fprintf(outfd, "%s(%ld, %ld, %ld, %ld, %ld, %ld)",
            get_syscall_name_abi(e->syscall_num, TRACY_ABI_NATIVE),
            (long) e->args.a0, (long) e->args.a1, (long) e->args.a2,
            (long) e->args.a3, (long) e->args.a4, (long) e->args.a5
        );
    }
}


/*********************** X64 specific functions ***********************/
#ifdef X64


#endif

/*********************** ARM32 specific functions ***********************/
#ifdef ARM32



#endif

/*********************** ARM64 specific functions ***********************/
#ifdef ARM64



#endif