/* fsmon -- MIT - Copyright NowSecure 2015-2019 - pancake@nowsecure.com  */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include "fsmon.h"

static FileMonitor fm = { 0 };
static bool firstnode = true;
static bool colorful = true;
static char* outputfpath = NULL;
static FILE* outfd = NULL;

FileMonitorBackend *backends[] = {
#if __APPLE__
	&fmb_devfsev,
	&fmb_kqueue,
	&fmb_kdebug,
#if !TARGET_WATCHOS
	&fmb_fsevapi,
#endif
#else
	&fmb_inotify,
#if HAVE_FANOTIFY
	&fmb_fanotify,
#endif
#endif
	NULL
};

static void control_c (int sig) {
	fm.running = false;
}

static bool setup_signals() {
	bool res = true;
	struct sigaction int_handler = {
		.sa_handler = control_c
	};
	if (sigaction (SIGINT, &int_handler, 0) == -1) {
		eprintf ("Cannot setup the SIGINT handler\n");
		res = false;
	}
	fm.running = true;
	if (fm.alarm) {
		if (sigaction (SIGALRM, &int_handler, 0) == -1) {
			eprintf ("Cannot setup the SIGALRM handler.\n");
			res = false;
		}
		if (alarm (fm.alarm) != 0) {
			eprintf ("Warning: A previous alarm was found.\n");
			res = false;
		}
	}
	return res;
}

static bool callback(FileMonitor *fm, FileMonitorEvent *ev) {
	if (fm->child) {
		if (fm->pid && ev->pid != fm->pid) {
			if (ev->ppid != fm->pid) {
				return false;
			}
		}
	} else {
		if (fm->pid && ev->pid != fm->pid) {
			return false;
		}
	}
	if (fm->root && ev->file) {
		if (strncmp (ev->file, fm->root, strlen (fm->root))) {
			return false;
		}
	}
	if (fm->link && ev->file) {
		if (!strncmp (ev->file, fm->link, strlen (fm->link))) {
			return false;
		}
	}
	if (fm->proc && ev->proc) {
		if (!strstr (ev->proc, fm->proc)) {
			return false;
		}
	}
	if (fm->json || fm->jsonStream) {
		if (fm->jsonStream) {
			firstnode = true;
		}
		char *filename = fmu_jsonfilter (ev->file);
		fprintf (outfd, "%s{\"filename\":\"%s\",\"pid\":%d,"
			"\"uid\":%d,\"gid\":%d,", 
			(fm->jsonStream || firstnode)? "":",", filename, ev->pid, ev->uid, ev->gid);
		firstnode = false;
		free (filename);
		if (ev->inode) {
			fprintf (outfd, "\"inode\":%d,", ev->inode);
		}
		if (ev->tstamp) {
			fprintf (outfd, "\"timestamp\":%" PRId64 ",", ev->tstamp);
		}
		if (ev->inode) {
			fprintf (outfd, "\"dev\":{\"major\":%d,\"minor\":%d},",
				ev->dev_major, ev->dev_minor);
		}
		if (ev->mode) {
			fprintf (outfd, "\"mode\":%d,", ev->mode);
		}
		if (ev->ppid) {
			fprintf (outfd, "\"ppid\":%d,", ev->ppid);
		}
		if (ev->proc && *ev->proc) {
			char *proc = fmu_jsonfilter (ev->proc);
			fprintf (outfd, "\"proc\":\"%s\",", proc);
			free (proc);
		}
		if (ev->event && *ev->event) {
			char *event = fmu_jsonfilter (ev->event);
			fprintf (outfd, "\"event\":\"%s\",", event);
			free (event);
		}
		if (ev->newfile && *ev->newfile) {
			char *filename = fmu_jsonfilter (ev->newfile);
			fprintf (outfd, "\"newfile\":\"%s\",", filename);
			free (filename);
		}
		fprintf (outfd, "\"type\":\"%s\"}", fm_typestr (ev->type));
		if (fm->jsonStream) {
			fprintf (outfd, "\n");
			fflush (outfd);
		}
	} else {
		if (fm->fileonly && ev->file) {
			const char *p = ev->file;
			for (p = p + strlen (p); p > ev->file; p--) {
				if (*p == '/')
					ev->file = p + 1;
			}
		}
		const char *color_begin = colorful? fm_colorstr (ev->type): "";
		const char *color_begin2 = colorful? Color_MAGENTA: "";
		const char *color_end = colorful? Color_RESET: "";
		// TODO . show event type
		if (ev->type == FSE_RENAME) {
			fprintf (outfd, "%s%s%s\t%d\t\"%s%s%s\"\t%s -> %s\n",
				color_begin, fm_typestr(ev->type), color_end,
				ev->pid, color_begin2, ev->proc? ev->proc: "", color_end, ev->file,
				ev->newfile);
		} else {
			fprintf (outfd, "%s%s%s\t%d\t\"%s%s%s\"\t%s\n",
				color_begin, fm_typestr(ev->type), color_end,
				ev->pid, color_begin2, ev->proc? ev->proc: "", color_end, ev->file);
		}
	}
	if (fm->link) {
		int i;
		char dst[1024];
		const char *src = ev->file;
		char *fname = strdup (ev->file);
		if (!fname) {
			eprintf ("Cannot allocate ev->file\n");
			return false;
		}
		for (i = 0; fname[i]; i++) {
			if (fname[i] == '/') {
				fname[i] = '_';
			}
		}
		if (ev->newfile) {
			src = ev->newfile;
		}
		if (is_directory (src)) {
			eprintf ("[I] Directories not copied\n");
		} else {
			snprintf (dst, sizeof (dst), "%s/%s", fm->link, fname);
			if (!copy_file (src, dst)) {
				eprintf ("[E] Error copying %s\n", dst);
			}
		}
		free (fname);
	}
	return false;
}

static void help (const char *argv0) {
	eprintf ("Usage: %s [-Jjc] [-a sec] [-b dir] [-B name] [-p pid] [-P proc] [path]\n"
		" -a [sec]          stop monitoring after N seconds (alarm)\n"
		" -b [dir]          backup files to DIR folder (EXPERIMENTAL)\n"
		" -B [name]         specify an alternative backend\n"
		" -c                follow children of -p PID or -e bin\n"
		" -f                show only filename (no path)\n"
		" -h                show this help\n"
		" -j                output in JSON format\n"
		" -J                output in JSON stream format\n"
		" -o [path]         write output to file\n"
		" -n                do not use colors\n"
		" -L                list all filemonitor backends\n"
		" -e [path/to/bin]  execute and monitor this binary\n"
		" -p [pid]          only show events from this pid\n"
		" -P [proc]         events only from process name\n"
		" -v                show version\n"
		" [path]            only get events from this path\n"
		, argv0);
}

static bool use_backend(const char *name) {
	int i;
	for (i = 0; backends[i]; i++) {
		if (!strcmp (backends[i]->name, name)) {
			fm.backend = *backends[i];
			return true;
		}
	}
	return false;
}

static void list_backends() {
	int i;
	for (i = 0; backends[i]; i++) {
		printf ("%s\n", backends[i]->name);
	}
}

static void swap_process(char* cmd) {
	if (execl(cmd, cmd, NULL) == -1) {
		eprintf("FATAL ERROR trying to spawn %s\n", cmd);
		exit(1);
	}
}

int main (int argc, char **argv) {
	int c, ret = 0;
#if __APPLE__
	fm.backend = fmb_devfsev;
#else
	fm.backend = fmb_inotify;
#endif

	while ((c = getopt (argc, argv, "a:chb:B:d:fjJo:Lne:p:P:v")) != -1) {
		switch (c) {
		case 'a':
			fm.alarm = atoi (optarg);
			if (fm.alarm < 1) {
				eprintf ("Invalid alarm time\n");
				return 1;
			}
			break;
		case 'b':
			fm.link = optarg;
			break;
		case 'B':
			use_backend (optarg);
			break;
		case 'c':
			fm.child = true;
			break;
		case 'h':
			help (argv[0]);
			return 0;
		case 'f':
			fm.fileonly = true;
			break;
		case 'j':
			fm.json = true;
			break;
		case 'J':
			fm.jsonStream = true;
			break;
		case 'o':
		{
			size_t pathlen = strnlen(optarg, FILENAME_MAX) + 1;
			outputfpath = malloc(pathlen * sizeof(char));
			if (!outputfpath) {
				eprintf("FATAL Could not allocate fname buffer!");
				exit(1);
			}
			strncpy(outputfpath, optarg, pathlen);
			break;
		}
		case 'L':
			list_backends ();
			return 0;
		case 'n':
			colorful = false;
			break;
		case 'e':
		{
			pid_t child_pid = fork();

			if (child_pid == 0) {
				// Child process
				swap_process(optarg);
			}
			else {
				fm.pid = (int) child_pid;
			}

			break;
		}
		case 'p':
			fm.pid = atoi (optarg);
			break;
		case 'P':
			fm.proc = optarg;
			break;
		case 'v':
			printf ("fsmon %s\n", FSMON_VERSION);
			return 0;
		}
	}

	if (optind < argc) {
		fm.root = argv[optind];
	}
	if (fm.child && !fm.pid) {
		eprintf ("-c requires -p or -e\n");
		return 1;
	}

	// Open a descriptor to the desired output
	if (outputfpath) {
		outfd = fopen(outputfpath, "a");
	}
	else {
		outfd = stdout;
	}

	if (fm.json && !fm.jsonStream) {
		fprintf (outfd, "[");
	}

	// Start processing FS events
	if (fm.backend.begin (&fm)) {
		(void)setup_signals ();
		fm.backend.loop (&fm, callback);
	} else {
		ret = 1;
	}

	// Processing finished => clean-up
	if (fm.json && !fm.jsonStream) {
		fprintf (outfd, "]\n");
	}

	fflush(outfd);
	fclose(outfd);
	fm.backend.end(&fm);
	if (outputfpath) free(outputfpath);

	return ret;
}
