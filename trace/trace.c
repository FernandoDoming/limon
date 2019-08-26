#include <pthread.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <stdbool.h>

#include "trace.h"
#include "fsmon.h"
#include "util.h"
#include "macro.h"

extern FILE* outfd;
extern FileMonitor fm;
extern bool firstnode;

struct tracy* init_tracing()
{
    struct tracy* tracy = tracy_init(TRACY_TRACE_CHILDREN);
    tracy_set_hook(tracy, "execve", TRACY_ABI_NATIVE, hook_execve);
    tracy_set_default_hook(tracy, hook_syscall);

    return tracy;
}

/*
 * Changes execurtable image to another one provided by cmd arg 
 * and trace it with ptrace. Should be run by a child proc
 */
void spawn_tracee_process(void* cmd)
{
    if (cmd == NULL) return;

	if (execl(cmd, cmd, NULL) == -1) {
		FATAL("ERROR trying to spawn %s", (char*) cmd);
	}
}

/****************** hooks ******************/

int hook_syscall(struct tracy_event* e) {
    print_syscall(e);
    return TRACY_HOOK_CONTINUE;
}

int hook_execve(struct tracy_event* e) {
    fprintf(
        outfd,
        "%s{\"event_type\":\"syscall\","
        "\"pid\":%d,"
        "\"syscall_name\":\"%s\","
        "\"syscall_n\":%ld,"
        "\"return\":%ld",
        (fm.jsonStream || firstnode) ? "" : ",",
        e->child->pid,
        get_syscall_name_abi(e->syscall_num, TRACY_ABI_NATIVE),
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
            fprintf(
                outfd,
                "\"%s\"",
                item->data
            );
            i++;
        }
        fprintf(outfd, "]");
    }

    fprintf(outfd, "}\n");

    while (item = TAILQ_FIRST(&argv_head)) {
        TAILQ_REMOVE(&argv_head, item, entries);
        free(item);
    }

    return TRACY_HOOK_CONTINUE;
}

/****************** utils ******************/

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
            "\"a5\":%ld,"
            "\"return\":%ld"
            "}\n",
            (fm.jsonStream || firstnode) ? "" : ",",
            e->child->pid,
            get_syscall_name_abi(e->syscall_num, TRACY_ABI_NATIVE),
            e->syscall_num,
            (long) e->args.a0, (long) e->args.a1, (long) e->args.a2,
            (long) e->args.a3, (long) e->args.a4, (long) e->args.a5,
            e->args.return_code
        );
    }
    else {
        fprintf(outfd, "%s(%ld, %ld, %ld, %ld, %ld, %ld) = %ld",
            get_syscall_name_abi(e->syscall_num, TRACY_ABI_NATIVE),
            (long) e->args.a0, (long) e->args.a1, (long) e->args.a2,
            (long) e->args.a3, (long) e->args.a4, (long) e->args.a5,
            e->args.return_code
        );
    }
}
