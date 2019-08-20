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

    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        FATAL("Process could not be traced: %s", strerror(errno));
    }

	if (execl(cmd, cmd, NULL) == -1) {
		FATAL("ERROR trying to spawn %s", (char*) cmd);
	}
}

/*
 * Function that consumes syscall events in a loopity loop.
 * Should be run in parent of tracee
 */
void* ptrace_syscall_mon_loop(void* optarg)
{
    if (optarg == NULL) return NULL;

    pid_t pid  = *(pid_t*) optarg;
    int status = 0;
    long ptrace_options = PTRACE_O_TRACESYSGOOD
                            | PTRACE_O_TRACEFORK
                            | PTRACE_O_TRACEVFORK
                            | PTRACE_O_TRACECLONE
                            | PTRACE_O_TRACEEXIT
                            | PTRACE_O_TRACEEXEC
                            | PTRACE_O_TRACEVFORKDONE;

    waitpid(pid, &status, __WALL);

    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, ptrace_options))
        FATAL("Could not set ptrace options - %s", strerror(errno));

    for (;;)
    {
#       ifdef X64
        x64_ptrace_loop(pid);
#       elif ARM32
        arm32_ptrace_loop(pid);
#       elif ARM64
        arm64_ptrace_loop(pid);
#       endif
    }

    return NULL;
}

/*********************** X64 specific functions ***********************/
#ifdef X64

void x64_ptrace_loop(pid_t pid)
{
    /* Enter next system call */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        FATAL("[ENTER] PTRACE_SYSCALL - %s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1)
        FATAL("[ENTER] waitpid - %s", strerror(errno));

    /* Gather system call arguments */
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        FATAL("GETREGS - %s", strerror(errno));
    
    print_syscall_x64(&regs, pid);

    /* Run system call and stop on exit */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        FATAL("[RUN] PTRACE_SYSCALL - %s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1)
        FATAL("[RUN] waitpid - %s", strerror(errno));

    /* Get system call result */
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        fputs(" = ?\n", stderr);
        if (errno == ESRCH)
            exit(regs.rdi); // system call was _exit(2) or similar
        FATAL("GETREGS - %s", strerror(errno));
    }

    /* Print system call result */
    fprintf(stderr, " = %ld\n", (long) regs.rax);   
}

void print_syscall_x64(struct user_regs_struct* regs, pid_t pid)
{
    long syscall = regs->orig_rax;

    /* Print a representation of the system call */
    if (fm.json || fm.jsonStream) {
        fprintf(
            outfd,
            "%s{\"event_type\":\"syscall\","
            "\"pid\":%d,"
            "\"syscall_name\":\"%s\","
            "\"syscall_n\":%ld,"
            "\"rdi\":%ld,"
            "\"rsi\":%ld,"
            "\"rdx\":%ld,"
            "\"r10\":%ld,"
            "\"r8\":%ld,"
            "\"r9\":%ld"
            "}\n",
            (fm.jsonStream || firstnode) ? "" : ",",
            pid,
            syscall_n_to_name(syscall),
            syscall,
            (long)regs->rdi, (long)regs->rsi, (long)regs->rdx,
            (long)regs->r10, (long)regs->r8,  (long)regs->r9
        );
    }
    else {
        fprintf(outfd, "%s(%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall_n_to_name(syscall),
                (long)regs->rdi, (long)regs->rsi, (long)regs->rdx,
                (long)regs->r10, (long)regs->r8,  (long)regs->r9);
    }
}

#endif

/*********************** ARM32 specific functions ***********************/
#ifdef ARM32

void arm32_ptrace_loop(pid_t pid)
{
    /* Enter next system call */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) FATAL("%s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1) FATAL("%s", strerror(errno));

    /* Gather system call arguments */
    struct user_regs regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        FATAL("%s", strerror(errno));
    
    print_syscall_arm32(&regs);

    /* Run system call and stop on exit */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        FATAL("%s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1)
        FATAL("%s", strerror(errno));

    /* Get system call result */
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        fputs(" = ?\n", stderr);
        if (errno == ESRCH)
            exit(regs.rdi); // system call was _exit(2) or similar
        FATAL("%s", strerror(errno));
    }

    /* Print system call result */
    fprintf(stderr, " = %ld\n", (long) regs.rax);   
}

#endif

/*********************** ARM64 specific functions ***********************/
#ifdef ARM64

void arm64_ptrace_loop(pid_t pid)
{
    /* Enter next system call */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) FATAL("%s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1) FATAL("%s", strerror(errno));

    /* Gather system call arguments */
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        FATAL("%s", strerror(errno));
    
    print_syscall_x64(&regs);

    /* Run system call and stop on exit */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        FATAL("%s", strerror(errno));
    if (waitpid(pid, 0, 0) == -1)
        FATAL("%s", strerror(errno));

    /* Get system call result */
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        fputs(" = ?\n", stderr);
        if (errno == ESRCH)
            exit(regs.rdi); // system call was _exit(2) or similar
        FATAL("%s", strerror(errno));
    }

    /* Print system call result */
    fprintf(stderr, " = %ld\n", (long) regs.rax);   
}

#endif