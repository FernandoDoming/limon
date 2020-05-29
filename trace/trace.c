#include <pthread.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <linux/limits.h>

#include "trace.h"
#include "fsmon.h"
#include "util.h"
#include "macro.h"
#include "types.h"

extern FILE* outfd;
extern FileMonitor fm;
extern bool firstnode;
extern bool bypassanti;
extern pthread_mutex_t output_lock;

struct tracy* init_tracing(pid_t tracee_pid)
{
    struct tracy* tracy = tracy_init(TRACY_TRACE_CHILDREN);
    tracy_set_signal_hook(tracy, signal_hook);

    tracy_set_hook(tracy, "ptrace", get_tracy_abi_for_proc(tracee_pid), hook_ptrace);
    tracy_set_hook(tracy, "write",  get_tracy_abi_for_proc(tracee_pid), hook_write);
    tracy_set_hook(tracy, "open",   get_tracy_abi_for_proc(tracee_pid), hook_open);
    tracy_set_hook(tracy, "openat", get_tracy_abi_for_proc(tracee_pid), hook_openat);
    tracy_set_hook(tracy, "clone",  get_tracy_abi_for_proc(tracee_pid), hook_clone);
    tracy_set_hook(tracy, "execve", get_tracy_abi_for_proc(tracee_pid), hook_execve);

    tracy_set_default_hook(tracy, hook_syscall);

    TAILQ_INIT(&pid_head);
    add_traced_proc(tracee_pid, 0);

    return tracy;
}

void free_tracing(struct tracy* tracy)
{
    tracy_free(tracy);

    pid_entry* item = NULL;
    while (item = TAILQ_FIRST(&pid_head)) {
        TAILQ_REMOVE(&pid_head, item, entries);
        free(item);
    }
}

void add_traced_proc(pid_t pid, pid_t ppid)
{
    pid_entry* item = malloc(sizeof(*item));
    if (!item) FATAL("malloc: Not enough resources to alloc pid_entry");
    item->pid  = pid;
    item->ppid = ppid;

    TAILQ_INSERT_TAIL(&pid_head, item, entries);
}

bool is_traced_proc(pid_t pid)
{
    pid_entry* item = NULL;
    TAILQ_FOREACH(item, &pid_head, entries) {
        if (item->pid == pid) return true;
    }

    return false;
}

/*
 * Changes execurtable image to another one provided by cmd arg
 * and trace it with ptrace. Should be run by a child proc
 */
void spawn_tracee_process(void* cmd)
{
    if (cmd == NULL) return;

    /* Obtain the path to the binary */
    char bin[BUFSIZE] = {};
    strncpy(bin, cmd, BUFSIZE);
    char* spc = strchr(bin, ' ');
    if (spc != NULL) *spc = '\0';

    /* Count number of args */
    int parts = 0;
    char* pch = cmd;
    while (pch != NULL) {
        pch = strchr(pch, ' ');
        if (pch) {
            parts++;
            pch++;
        }
    }
    parts++;

    /* Split the cmd into the argv format */
    char** args = NULL;
    args = (char*) calloc(parts + 1, sizeof(char*));
    if (args == NULL) FATAL("Not enough resources");

    char* delimiter = strtok(cmd, " ");
    int i = 0;
    while (delimiter != NULL) {
        args[i] = delimiter;
        delimiter = strtok(NULL, " ");
        i++;
    }
    args[i] = NULL;

	if (execv(bin, args) == -1) {
		FATAL("ERROR trying to spawn %s\n", (char*) cmd);
	}
}

/****************** hooks ******************/

int signal_hook(struct tracy_event *e) {
    fprintf(
        outfd,
        "%s{\"event_type\":\"signal\","
        "\"timestamp\":%lu,"
        "\"pid\":%d,"
        "\"signum\":%ld,"
        "\"signame\":\"%s\","
        "\"si_code\":%d,"
        "\"si_status\":%d,"
        "\"si_pid\":%d}\n",
        (fm.jsonStream || firstnode) ? "" : ",",
        time(NULL),
        e->child->pid,
        e->signal_num,
        get_signal_name(e->signal_num),
        e->siginfo.si_code,
        e->siginfo.si_status,
        e->siginfo.si_pid
    );

    return TRACY_HOOK_CONTINUE;
}

int hook_syscall(struct tracy_event* e) {
    pthread_mutex_lock(&output_lock);
    print_syscall(e);
    pthread_mutex_unlock(&output_lock);

    return TRACY_HOOK_CONTINUE;
}

int hook_ptrace(struct tracy_event* e)
{
    if (e->child->pre_syscall) return TRACY_HOOK_CONTINUE;

    pthread_mutex_lock(&output_lock);

    fprintf(
        outfd,
        "%s{\"event_type\":\"syscall\","
        "\"timestamp\":%lu,"
        "\"pid\":%d,"
        "\"syscall_name\":\"%s\","
        "\"syscall_n\":%ld,"
        "\"request\":%ld,"
        "\"requested_pid\":%ld,"
        "\"addr\":%ld,"
        "\"data\":%ld,"
        "\"return\":%ld,",
        (fm.jsonStream || firstnode) ? "" : ",",
        time(NULL),
        e->child->pid,
        get_syscall_name_abi(e->syscall_num, get_tracy_abi_for_proc(e->child->pid)),
        e->syscall_num,
        e->args.a0,
        e->args.a1,
        e->args.a2,
        e->args.a3,
        e->args.return_code
    );

    if (bypassanti &&
        ((is_traced_proc(e->args.a1) && e->args.a0 == PTRACE_ATTACH) ||
            e->args.a0 == PTRACE_TRACEME))
    {
        e->args.return_code = 0;
        tracy_modify_syscall_regs(e->child, e->args.syscall, &e->args);
    }

    pthread_mutex_unlock(&output_lock);

    return TRACY_HOOK_CONTINUE;
}

int hook_clone(struct tracy_event* e)
{
    if (e->args.return_code > 0) {
        add_traced_proc(e->args.return_code, e->child->pid);

        pthread_mutex_lock(&output_lock);
        fprintf(
            outfd,
            "%s{\"event_type\":\"syscall\","
            "\"timestamp\":%lu,"
            "\"pid\":%d,"
            "\"syscall_name\":\"%s\","
            "\"syscall_n\":%ld,"
            "\"return\":%ld}\n",
            (fm.jsonStream || firstnode) ? "" : ",",
            time(NULL),
            e->child->pid,
            get_syscall_name_abi(e->syscall_num, get_tracy_abi_for_proc(e->child->pid)),
            e->syscall_num,
            e->args.return_code
        );
        pthread_mutex_unlock(&output_lock);
    }

    return TRACY_HOOK_CONTINUE;
}

int hook_open(struct tracy_event* e)
{
    pthread_mutex_lock(&output_lock);

    fprintf(
        outfd,
        "%s{\"event_type\":\"syscall\","
        "\"timestamp\":%lu,"
        "\"pid\":%d,"
        "\"syscall_name\":\"%s\","
        "\"syscall_n\":%ld,"
        "\"return\":%ld,",
        (fm.jsonStream || firstnode) ? "" : ",",
        time(NULL),
        e->child->pid,
        get_syscall_name_abi(e->syscall_num, get_tracy_abi_for_proc(e->child->pid)),
        e->syscall_num,
        e->args.return_code
    );

    char buffer[BUFSIZE] = {};
    read_remote_string(e, (char*) e->args.a0, buffer, BUFSIZE);

    fprintf(
        outfd,
        "\"filename\":"
    );

    print_scaped_string(outfd, buffer, BUFSIZE);

    fprintf(
        outfd,
        ","
    );

    fprintf(
        outfd,
        "\"flags\":%ld,"
        "\"mode\":%ld}\n",
        e->args.a1,
        e->args.a2
    );

    pthread_mutex_unlock(&output_lock);
    return TRACY_HOOK_CONTINUE;
}

int hook_openat(struct tracy_event* e)
{
    pthread_mutex_lock(&output_lock);

    fprintf(
        outfd,
        "%s{\"event_type\":\"syscall\","
        "\"timestamp\":%lu,"
        "\"pid\":%d,"
        "\"syscall_name\":\"%s\","
        "\"syscall_n\":%ld,"
        "\"return\":%ld,",
        (fm.jsonStream || firstnode) ? "" : ",",
        time(NULL),
        e->child->pid,
        get_syscall_name_abi(e->syscall_num, get_tracy_abi_for_proc(e->child->pid)),
        e->syscall_num,
        e->args.return_code
    );

    char buffer[BUFSIZE] = {};
    read_remote_string(e, (char*) e->args.a1, buffer, BUFSIZE);

    fprintf(
        outfd,
        "\"filename\":\""
    );
    print_scaped_string(outfd, buffer, BUFSIZE);
    fprintf(
        outfd,
        "\","
    );

    fprintf(
        outfd,
        "\"dfd\":%ld,"
        "\"flags\":%ld,"
        "\"mode\":%ld}\n",
        e->args.a0,
        e->args.a2,
        e->args.a3
    );

    pthread_mutex_unlock(&output_lock);
    return TRACY_HOOK_CONTINUE;
}

int hook_write(struct tracy_event* e)
{
    pthread_mutex_lock(&output_lock);
    fprintf(
        outfd,
        "%s{\"event_type\":\"syscall\","
        "\"timestamp\":%lu,"
        "\"pid\":%d,"
        "\"syscall_name\":\"%s\","
        "\"syscall_n\":%ld,"
        "\"return\":%ld,",
        (fm.jsonStream || firstnode) ? "" : ",",
        time(NULL),
        e->child->pid,
        get_syscall_name_abi(e->syscall_num, get_tracy_abi_for_proc(e->child->pid)),
        e->syscall_num,
        e->args.return_code
    );

    char fdpath[PATH_MAX] = {};
    char fd_symlink_path[PATH_MAX] = {};
    snprintf(fd_symlink_path, PATH_MAX, "/proc/%d/fd/%ld", e->child->pid, e->args.a0);
    if (realpath(fd_symlink_path, fdpath) == NULL) {
        snprintf(fdpath, PATH_MAX, "RESOLV_ERROR");
    }

    char buffer[BUFSIZE] = {};
    read_remote_string(e, (char*) e->args.a1, buffer, BUFSIZE);

    fprintf(
        outfd,
        "\"fd\":%ld,"
        "\"filepath\":\"",
        e->args.a0
    );
    print_scaped_string(outfd, fdpath, PATH_MAX);

    fprintf(outfd, "\",\"buffer\":\"");
    print_scaped_string(outfd, buffer, BUFSIZE);

    fprintf(
        outfd,
        "\","
        "\"count\":%ld}\n",
        e->args.a2
    );

    pthread_mutex_unlock(&output_lock);
    return TRACY_HOOK_CONTINUE;
}

int hook_execve(struct tracy_event* e) {
    pthread_mutex_lock(&output_lock);
    fprintf(
        outfd,
        "%s{\"event_type\":\"syscall\","
        "\"timestamp\":%lu,"
        "\"pid\":%d,"
        "\"syscall_name\":\"%s\","
        "\"syscall_n\":%ld,"
        "\"return\":%ld,",
        (fm.jsonStream || firstnode) ? "" : ",",
        time(NULL),
        e->child->pid,
        get_syscall_name_abi(e->syscall_num, get_tracy_abi_for_proc(e->child->pid)),
        e->syscall_num,
        e->args.return_code
    );

    /* Read the remote binary path */
    char binpath[BUFSIZE] = {};
    tracy_read_mem(
        e->child,
        binpath,
        (tracy_child_addr_t) e->args.a0,
        BUFSIZE
    );

    fprintf(
        outfd,
        "\"filename\":\"%s\"",
        binpath
    );

    /* Read remote argv list */
    str_list_entry* item = NULL;
    TAILQ_INIT(&argv_head);

    size_t argc = read_remote_string_array(
        e, (char**) e->args.a1,
        &argv_head
    );

    if (argc > 0)
    {
        fprintf(outfd, ",\"args\": [");

        unsigned char i = 0;
        TAILQ_FOREACH(item, &argv_head, entries) {
            if (i > 0) {
                fprintf(outfd, ",");
            }
            fprintf(outfd, "\"");
            print_scaped_string(outfd, item->data, 1024);
            fprintf(outfd, "\"");
            i++;
        }
        fprintf(outfd, "]");
    }

    fprintf(outfd, "}\n");
    pthread_mutex_unlock(&output_lock);

    while (item = TAILQ_FIRST(&argv_head)) {
        TAILQ_REMOVE(&argv_head, item, entries);
        free(item);
    }

    return TRACY_HOOK_CONTINUE;
}

/****************** utils ******************/

size_t read_remote_string(
    struct tracy_event* e,
    char* rstring,
    char* buffer,
    size_t buflen
)
{
    if (rstring == NULL || buffer == NULL) return 0;

    tracy_read_mem(e->child, buffer, rstring, buflen);
    return strnlen(buffer, buflen);
}

size_t read_remote_string_array(
    struct tracy_event* e,
    char** rtable,
    struct argv_q* argv_head
)
{
    if (rtable == NULL) return 0;

    str_list_entry* item = NULL;
    size_t nread = 0;

    while(true)
    {
        char* rstr = NULL;
        tracy_read_mem(e->child, &rstr, rtable + nread, sizeof(char*));
        if (rstr == NULL) break;

        item = malloc(sizeof(str_list_entry));
        if (item == NULL) return 0;

        tracy_read_mem(e->child, item->data, rstr, BUFSIZE);
        TAILQ_INSERT_TAIL(argv_head, item, entries);

        nread++;
    }

    return nread;
}

long get_tracy_abi_for_proc(pid_t pid)
{
#   ifdef __x86_64__
    if (is_32bit_process(pid)) return TRACY_ABI_X86;
#   endif

    return TRACY_ABI_NATIVE;
}

void print_syscall(struct tracy_event* e)
{
    /* Print a representation of the system call */
    if (fm.json || fm.jsonStream) {
        fprintf(
            outfd,
            "%s{\"event_type\":\"syscall\","
            "\"timestamp\":%lu,"
            "\"pid\":%d,"
            "\"syscall_name\":\"%s\","
            "\"syscall_n\":%ld,"
            "\"a0\":%ld,"
            "\"a1\":%ld,"
            "\"a2\":%ld,"
            "\"a3\":%ld,"
            "\"a4\":%ld,"
            "\"a5\":%ld,"
            "\"return\":%ld"
            "}\n",
            (fm.jsonStream || firstnode) ? "" : ",",
            time(NULL),
            e->child->pid,
            get_syscall_name_abi(e->syscall_num, get_tracy_abi_for_proc(e->child->pid)),
            e->syscall_num,
            (long) e->args.a0, (long) e->args.a1, (long) e->args.a2,
            (long) e->args.a3, (long) e->args.a4, (long) e->args.a5,
            e->args.return_code
        );
    }
    else {
        fprintf(outfd, "%s(%ld, %ld, %ld, %ld, %ld, %ld) = %ld",
            get_syscall_name_abi(e->syscall_num, get_tracy_abi_for_proc(e->child->pid)),
            (long) e->args.a0, (long) e->args.a1, (long) e->args.a2,
            (long) e->args.a3, (long) e->args.a4, (long) e->args.a5,
            e->args.return_code
        );
    }
}
