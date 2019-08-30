#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include "macro.h"

typedef struct _str_list_entry {
    TAILQ_ENTRY(_str_list_entry) entries;
    char data[BUFSIZE];
} str_list_entry;

typedef struct _pid_entry {
    TAILQ_ENTRY(_str_list_entry) entries;
    pid_t pid;
    pid_t ppid;
} pid_entry;