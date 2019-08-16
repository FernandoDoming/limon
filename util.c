/* fsmon -- MIT - Copyright NowSecure 2015-2016 - pancake@nowsecure.com */

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#if __APPLE__
#include <sys/sysctl.h>
#endif
#if __linux__
#include <linux/limits.h>
#endif
#include <errno.h>
#include "fsmon.h"

// Can be regenerated with
// { echo "char* syscalls[] = {"; ausyscall --dump | awk '{ print "\t\"" $2 "\"," }'; echo "};" } > file
char* syscalls[] = {
	"read",
	"write",
	"open",
	"close",
	"stat",
	"fstat",
	"lstat",
	"poll",
	"lseek",
	"mmap",
	"mprotect",
	"munmap",
	"brk",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigreturn",
	"ioctl",
	"pread",
	"pwrite",
	"readv",
	"writev",
	"access",
	"pipe",
	"select",
	"sched_yield",
	"mremap",
	"msync",
	"mincore",
	"madvise",
	"shmget",
	"shmat",
	"shmctl",
	"dup",
	"dup2",
	"pause",
	"nanosleep",
	"getitimer",
	"alarm",
	"setitimer",
	"getpid",
	"sendfile",
	"socket",
	"connect",
	"accept",
	"sendto",
	"recvfrom",
	"sendmsg",
	"recvmsg",
	"shutdown",
	"bind",
	"listen",
	"getsockname",
	"getpeername",
	"socketpair",
	"setsockopt",
	"getsockopt",
	"clone",
	"fork",
	"vfork",
	"execve",
	"exit",
	"wait4",
	"kill",
	"uname",
	"semget",
	"semop",
	"semctl",
	"shmdt",
	"msgget",
	"msgsnd",
	"msgrcv",
	"msgctl",
	"fcntl",
	"flock",
	"fsync",
	"fdatasync",
	"truncate",
	"ftruncate",
	"getdents",
	"getcwd",
	"chdir",
	"fchdir",
	"rename",
	"mkdir",
	"rmdir",
	"creat",
	"link",
	"unlink",
	"symlink",
	"readlink",
	"chmod",
	"fchmod",
	"chown",
	"fchown",
	"lchown",
	"umask",
	"gettimeofday",
	"getrlimit",
	"getrusage",
	"sysinfo",
	"times",
	"ptrace",
	"getuid",
	"syslog",
	"getgid",
	"setuid",
	"setgid",
	"geteuid",
	"getegid",
	"setpgid",
	"getppid",
	"getpgrp",
	"setsid",
	"setreuid",
	"setregid",
	"getgroups",
	"setgroups",
	"setresuid",
	"getresuid",
	"setresgid",
	"getresgid",
	"getpgid",
	"setfsuid",
	"setfsgid",
	"getsid",
	"capget",
	"capset",
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"sigaltstack",
	"utime",
	"mknod",
	"uselib",
	"personality",
	"ustat",
	"statfs",
	"fstatfs",
	"sysfs",
	"getpriority",
	"setpriority",
	"sched_setparam",
	"sched_getparam",
	"sched_setscheduler",
	"sched_getscheduler",
	"sched_get_priority_max",
	"sched_get_priority_min",
	"sched_rr_get_interval",
	"mlock",
	"munlock",
	"mlockall",
	"munlockall",
	"vhangup",
	"modify_ldt",
	"pivot_root",
	"_sysctl",
	"prctl",
	"arch_prctl",
	"adjtimex",
	"setrlimit",
	"chroot",
	"sync",
	"acct",
	"settimeofday",
	"mount",
	"umount2",
	"swapon",
	"swapoff",
	"reboot",
	"sethostname",
	"setdomainname",
	"iopl",
	"ioperm",
	"create_module",
	"init_module",
	"delete_module",
	"get_kernel_syms",
	"query_module",
	"quotactl",
	"nfsservctl",
	"getpmsg",
	"putpmsg",
	"afs_syscall",
	"tuxcall",
	"security",
	"gettid",
	"readahead",
	"setxattr",
	"lsetxattr",
	"fsetxattr",
	"getxattr",
	"lgetxattr",
	"fgetxattr",
	"listxattr",
	"llistxattr",
	"flistxattr",
	"removexattr",
	"lremovexattr",
	"fremovexattr",
	"tkill",
	"time",
	"futex",
	"sched_setaffinity",
	"sched_getaffinity",
	"set_thread_area",
	"io_setup",
	"io_destroy",
	"io_getevents",
	"io_submit",
	"io_cancel",
	"get_thread_area",
	"lookup_dcookie",
	"epoll_create",
	"epoll_ctl_old",
	"epoll_wait_old",
	"remap_file_pages",
	"getdents64",
	"set_tid_address",
	"restart_syscall",
	"semtimedop",
	"fadvise64",
	"timer_create",
	"timer_settime",
	"timer_gettime",
	"timer_getoverrun",
	"timer_delete",
	"clock_settime",
	"clock_gettime",
	"clock_getres",
	"clock_nanosleep",
	"exit_group",
	"epoll_wait",
	"epoll_ctl",
	"tgkill",
	"utimes",
	"vserver",
	"mbind",
	"set_mempolicy",
	"get_mempolicy",
	"mq_open",
	"mq_unlink",
	"mq_timedsend",
	"mq_timedreceive",
	"mq_notify",
	"mq_getsetattr",
	"kexec_load",
	"waitid",
	"add_key",
	"request_key",
	"keyctl",
	"ioprio_set",
	"ioprio_get",
	"inotify_init",
	"inotify_add_watch",
	"inotify_rm_watch",
	"migrate_pages",
	"openat",
	"mkdirat",
	"mknodat",
	"fchownat",
	"futimesat",
	"newfstatat",
	"unlinkat",
	"renameat",
	"linkat",
	"symlinkat",
	"readlinkat",
	"fchmodat",
	"faccessat",
	"pselect6",
	"ppoll",
	"unshare",
	"set_robust_list",
	"get_robust_list",
	"splice",
	"tee",
	"sync_file_range",
	"vmsplice",
	"move_pages",
	"utimensat",
	"epoll_pwait",
	"signalfd",
	"timerfd",
	"eventfd",
	"fallocate",
	"timerfd_settime",
	"timerfd_gettime",
	"accept4",
	"signalfd4",
	"eventfd2",
	"epoll_create1",
	"dup3",
	"pipe2",
	"inotify_init1",
	"preadv",
	"pwritev",
	"rt_tgsigqueueinfo",
	"perf_event_open",
	"recvmmsg",
	"fanotify_init",
	"fanotify_mark",
	"prlimit64",
	"name_to_handle_at",
	"open_by_handle_at",
	"clock_adjtime",
	"syncfs",
	"sendmmsg",
	"setns",
	"getcpu",
	"process_vm_readv",
	"process_vm_writev",
	"kcmp",
	"finit_module",
	"sched_setattr",
	"sched_getattr",
	"renameat2",
	"seccomp",
	"getrandom",
	"memfd_create",
	"kexec_file_load",
	"bpf",
	"execveat",
	"userfaultfd",
	"membarrier",
	"mlock2",
	"copy_file_range",
	"preadv2",
	"pwritev2",
	"pkey_mprotect",
	"pkey_alloc",
	"pkey_free",
	"statx",
};

char* syscall_n_to_name(long syscall_n)
{
    return syscalls[syscall_n];
}

void hexdump(const uint8_t *buf, unsigned int len, int w) {
	unsigned int i, j;
	if (w < 1) {
		w = 16;
	}
	for (i = 0; i < len; i += w) {
		printf ("0x%08x: ", i);
		for (j = i; j < i + w; j++) {
			if (j < len) {
				printf (j%2 ? "%02x ":"%02x", buf[j]);
			} else {
				printf (j%2 ? "   " : "  ");
			}
		}
		printf (" ");
		for (j = i; j < i + w; j++) {
			printf ("%c", isprint (buf[j])? buf[j]: '.');
		}
		printf ("\n");
	}
}

const char *fm_typestr(int type) {
#define __(x) [x]=#x
	const char *types[FSE_MAX_EVENTS] = {
		__ (FSE_CREATE_FILE),
		__ (FSE_DELETE),
		__ (FSE_STAT_CHANGED),
		__ (FSE_RENAME),
		__ (FSE_CONTENT_MODIFIED),
		__ (FSE_CREATE_DIR),
		__ (FSE_CHOWN),
		__ (FSE_EXCHANGE),
		__ (FSE_FINDER_INFO_CHANGED),
		__ (FSE_XATTR_MODIFIED),
		__ (FSE_XATTR_REMOVED),
	};
	switch (type) {
	case FSE_ARG_DONE: return "FSE_ARG_DONE";
	case FSE_OPEN: return "FSE_OPEN";
	case FSE_UNKNOWN: return "FSE_UNKNOWN";
	}
	return (type >= 0 && type < FSE_MAX_EVENTS && types[type])? types[type]: "";
}

const char *fm_argstr(int type) {
#define __(x) [x]=#x
	const char *args[13] = {
		__ (FSE_ARG_NONE),
		__ (FSE_ARG_VNODE),
		__ (FSE_ARG_STRING),
		__ (FSE_ARG_PATH),
		__ (FSE_ARG_INT32),
		__ (FSE_ARG_INT64),
		__ (FSE_ARG_RAW),
		__ (FSE_ARG_INO),
		__ (FSE_ARG_UID),
		__ (FSE_ARG_DEV),
		__ (FSE_ARG_MODE),
		__ (FSE_ARG_GID),
		__ (FSE_ARG_FINFO),
	};
	switch (type) {
	case FSE_ARG_DONE: return "FSE_ARG_DONE";
	case 0: return "FSE_UNKNOWN";
	}
	return (type >= 0 && type < FSE_MAX_EVENTS && args[type])? args[type]: "";
}

const char *fm_colorstr(int type) {
	const char *colors[FSE_MAX_EVENTS] = {
		Color_MAGENTA,// FSE_CREATE_FILE
		Color_RED,    // FSE_DELETE
		Color_YELLOW, // FSE_STAT_CHANGED
		Color_GREEN,  // FSE_RENAME
		Color_YELLOW, // FSE_CONTENT_MODIFIED
		Color_BLUE,   // FSE_CREATE_DIR
		Color_YELLOW, // FSE_CHOWN
		Color_GREEN,  // FSE_EXCHANGE
		Color_YELLOW, // FSE_FINDER_INFO_CHANGED
		Color_YELLOW, // FSE_XATTR_MODIFIED,
		Color_RED,    // FSE_XATTR_REMOVED,
	};
	switch (type) {
	case FSE_ARG_DONE: return Color_GREEN;
	case FSE_OPEN: return Color_GREEN;
	case FSE_UNKNOWN: return Color_RED;
	}
	return (type >= 0 && type < FSE_MAX_EVENTS)? colors[type]: "";
}

const char *get_proc_name(int pid, int *ppid) {
	static char path[PATH_MAX] = {0};
#if __APPLE__
	struct kinfo_proc * kinfo = (struct kinfo_proc*)&path;
	size_t len = 1000;
	int rc, mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;

	memset (path, 0, sizeof (path));
	if ((rc = sysctl (mib, 4, path, &len, NULL, 0)) != 0) {
		perror("trace facility failure, KERN_PROC_PID\n");
		exit (1);
	}

	if (ppid) *ppid = kinfo->kp_eproc.e_ppid;
	return kinfo->kp_proc.p_comm;
#elif __linux__
	char *p, *q;
	int fd;
	snprintf (path, sizeof (path), "/proc/%d/stat", pid);
	fd = open (path, O_RDONLY);
	if (fd == -1) {
		// eprintf ("Cannot open '%s'\n", path);
		return NULL;
	}
	path[0] = 0;
	(void) read (fd, path, sizeof (path));
	path[sizeof (path) - 1] = 0;
	close (fd);
	p = strchr (path, '(');
	q = strchr (path, ')');

	if (p && q && p < q && q[1] && q[2]) {
		*q = 0;
		if (ppid) {
			char *r = strchr (q + 2, ' ');
			if (r) *ppid = atoi (r + 1);
		}
		return p + 1;
	}
	return NULL;
#else
#warning getProcName not supported for this platform
	return NULL;
#endif
}

bool is_directory (const char *str) {
        struct stat buf = {0};
        if (!str || !*str) {
		return false;
	}
        if (stat (str, &buf) == -1) {
		return false;
	}
        if ((S_IFBLK & buf.st_mode) == S_IFBLK) {
		return false;
	}
        return S_IFDIR == (S_IFDIR & buf.st_mode);
}

bool copy_file(const char *src, const char *dst) {
	char buf[4096];
	struct stat stat_src;
	int count, mode = 0640;
	int fd_src, fd_dst;
	fd_src = open (src, O_RDONLY);
	if (fd_src == -1) {
		perror ("open");
		return false;
	}
	if (!fstat (fd_src, &stat_src)) {
		mode = stat_src.st_mode;
	}
	fd_dst = open (dst, O_RDWR | O_CREAT | O_TRUNC, mode);
	if (fd_dst == -1) {
		(void) close (fd_src);
		return false;
	}
	for (;;) {
		count = read (fd_src, buf, sizeof (buf));
		if (count < 1) {
			break;
		}
		(void) write (fd_dst, buf, count);
	}
	(void) close (fd_src);
	(void) close (fd_dst);
	return true;
}

static bool isPrintable(const char ch) {
	if (ch == '"' || ch == '\\') {
		return false;
	}
	return IS_PRINTABLE (ch);
}

char *fmu_jsonfilter(const char *s) {
	char *r, *R = strdup (s);
	for (r = R; *r; ) {
		if (isPrintable (*r)) {
			r++;
		} else {
			memmove (r, r + 1, strlen (r) + 1);
		}
	}
	return R;
}
