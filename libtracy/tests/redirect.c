/*
    This file is part of Tracy.

    Tracy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tracy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tracy.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "../tracy.h"
#include "../ll.h"

#include <stdio.h>
#include <stdlib.h>

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>

#include <string.h>

int hook_write(struct tracy_event *e) {
    struct tracy_sc_args a;

    if (e->child->pre_syscall) {
        if (e->args.a0 == 2) {
            memcpy(&a, &(e->args), sizeof(struct tracy_sc_args));
            a.a0 = 1;
            if (tracy_modify_syscall_args(e->child, a.syscall, &a)) {
                return TRACY_HOOK_ABORT;
            }
        }
    }

    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
    tracy = tracy_init(TRACY_TRACE_CHILDREN);
    tracy_set_hook(tracy, "write", TRACY_ABI_NATIVE, hook_write);
#ifdef __x86_64__
    tracy_set_hook(tracy, "write", TRACY_ABI_X86, hook_write);
#endif
    /*tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE);*/

    if (argc < 2) {
        printf("Usage: ./example <program-name>\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;

    /* Start child */
    if (!tracy_exec(tracy, argv)) {
        perror("tracy_exec");
        return EXIT_FAILURE;
    }

    /* Main event-loop */
    tracy_main(tracy);

    tracy_free(tracy);

    return EXIT_SUCCESS;
}
