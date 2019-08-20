#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "../trampy.h"

static void _handle_sigusr1(int sig, siginfo_t *info, void *p)
{
    printf("Received signal %d from process %d, pointer %p\n", sig,
        info->si_pid, p);

    exit(EXIT_SUCCESS);
    return;
}

int main()
{
    pid_t pid;
    void *safe_entry;
    struct sigaction s;

    pid = getpid();
    printf("My PID is: %d\n", pid);
    safe_entry= trampy_get_safe_entry();

    s.sa_sigaction = _handle_sigusr1;
    sigemptyset(&s.sa_mask);
    s.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &s, NULL);

    #ifdef __i386__
    __asm__(
        "call *%%eax"
        ::
        "a"(safe_entry),
        "D"(pid)
    );
    #elif defined(__x86_64__)
    __asm__(
        "mov %%rdx, %%r8\n"
        "call *%%rax"
        ::
        "a"(safe_entry),
        "rdx"(pid)
    );
    #elif defined(__arm__)
    __asm__(
        "ldr r0, %0\n"
        "ldr r4, %1\n"
        "mov pc, r0"
        ::
        "Q"(safe_entry),
        "Q"(pid)
    );
    #endif

    return 0;
}

