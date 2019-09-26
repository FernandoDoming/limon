/* EZ PZ lemon squeezy */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include "fsmon.h"
#include "trace.h"
#include "tracy.h"
#include "macro.h"

static bool colorful = true;
static char* outfpath = NULL;

bool firstnode = true;
FileMonitor fm = {};
FILE* outfd    = NULL;
pthread_mutex_t output_lock = {};

FileMonitorBackend *backends[] = {
	&fmb_inotify,
#if HAVE_FANOTIFY
	&fmb_fanotify,
#endif
	NULL
};

static void help (const char *argv0) {
	eprintf ("Usage: %s [options] [filemonitor/root/path]\n"
		" -b [dir]          backup files to DIR folder (EXPERIMENTAL)\n"
		" -B [name]         specify an alternative backend\n"
		" -f                show only filename (no path)\n"
		" -h                show this help\n"
		" -j                output in JSON format\n"
		" -J                output in JSON stream format\n"
		" -o [path]         write output to file\n"
		" -n                do not use colors\n"
		" -L                list all filemonitor backends\n"
		" -e [path/to/bin]  execute and monitor this binary\n"
		" -v                show version\n"
		" [path]            only get events from this path\n"
		, argv0);
}

static void control_c (int sig) {
	fm.running = false;
}

bool setup_signals() {
	bool res = true;
	struct sigaction int_handler = {
		.sa_handler = control_c
	};
	if (sigaction (SIGINT, &int_handler, 0) == -1) {
		eprintf("Cannot setup the SIGINT handler\n");
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

bool callback(FileMonitor *fm, FileMonitorEvent *ev) {
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

		pthread_mutex_lock(&output_lock);
		fprintf (outfd,
			"%s{\"event_type\":\"fsevent\","
			"\"filename\":\"%s\",\"pid\":%d,"
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

		pthread_mutex_unlock(&output_lock);

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

static void* start_fsmon(void* arg)
{
	if (arg == NULL) return NULL;
	FileMonitor* fm = (FileMonitor*) arg;

	fm->backend.loop(fm, callback);
	return NULL;
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

int main (int argc, char **argv) {
	int c, ret = 0;
	char* binpath = NULL;
	fm.backend  = fmb_fanotify;
	fm.child    = true;

	/* Cmdline option parsing */
	while ((c = getopt (argc, argv, "hb:B:d:fjJo:Lne:p:P:v")) != -1) {
		switch (c) {
		case 'b':
			fm.link = optarg;
			break;
		case 'B':
			use_backend(optarg);
			break;
		case 'h':
			help(argv[0]);
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
			outfpath = (char*) malloc(pathlen * sizeof(char));
			if (!outfpath) {
				FATAL("Could not allocate fname buffer!");
			}
			strncpy(outfpath, optarg, pathlen - 1);
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
			size_t pathlen = strnlen(optarg, FILENAME_MAX) + 1;
			binpath = (char*) malloc(pathlen * sizeof(char));
			if (!binpath) {
				FATAL("Could not allocate binpath buffer!\n");
			}
			strncpy(binpath, optarg, pathlen - 1);
			break;
		}
		case 'v':
			print_version();
			return 0;
		}
	}

	/* Check for errors in the arguments */
	if (!fm.pid && !binpath) {
		FATAL("Either -p or -e are mandatory");
	}
	if (optind < argc) {
		fm.root = argv[optind];
	}

	/* Open a descriptor to the desired output */
	if (outfpath) {
		outfd = fopen(outfpath, "a");
	}
	else {
		outfd = stdout;
	}

	if (fm.json && !fm.jsonStream) {
		fprintf (outfd, "[");
	}

	/******** Event processing ********/
	/* fsmon events */
	pid_t child_pid  = fm.pid;
	pthread_t fs_tid = -1;

	pthread_mutex_init(&output_lock, NULL);

	if (binpath)
	{
		child_pid = fork();
		if (child_pid == 0) {
			/* Child (tracee) */
			spawn_tracee_process(binpath);
		}

		/* Parent (tracer) */
		fm.pid = (int) child_pid;
	}

	if (fm.backend.begin(&fm)) {
		(void) setup_signals();
		/* Spawn a threat to consume FS events so we don't block */
		pthread_create(&fs_tid, NULL, start_fsmon, &fm);
	}
	else {
		perror("[!] ERROR FSMON could not be started ...");
	}

	/* ptrace events */
	if (child_pid)
	{
		struct tracy* tracy = init_tracing(child_pid);
		tracy_attach(tracy, child_pid);
		tracy_main(tracy);			// Blocking syscall loop

		free_tracing(tracy);
	}

	/* Monitored proccess exited, cleanup and exit */
	if (fm.json && !fm.jsonStream) {
		fprintf(outfd, "]\n");
	}

	pthread_mutex_destroy(&output_lock);
	fflush(outfd);
	fclose(outfd);
	fm.running = false;
	fm.backend.end(&fm);
	if (outfpath) free(outfpath);
	if (binpath)  free(binpath);

	return ret;
}
