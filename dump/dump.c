#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include "dump.h"
#include "macro.h"

bool dump_pid(unsigned int pid, char* dumpdir)
{
	bool success = true;
	char memmappath[PATH_MAX] = {};
	snprintf (memmappath, PATH_MAX, "/proc/%d/maps", pid);

	FILE* f_memmap = fopen(memmappath, "r");
	if (f_memmap == NULL) {
		success = false;
		fprintf(stderr, "E: Could not open %s to dump pid %u\n", memmappath, pid);
		goto cleanup;
	}

	// Read mem map file
	// example line: 564d35d9b000-564d35d9d000 r--p 00000000 08:03 6029461                    /usr/bin/cat
	char line[BUFSIZE] = {};
	while(fgets(line, BUFSIZE, f_memmap)) {
		unsigned long from = 0, to = 0, pgoff = 0;
		unsigned int major = 0, minor = 0, ino = 0;
		char flags[4] = {};
		char fpath[PATH_MAX] = {};

		sscanf(
			line,
			"%lx-%lx %c%c%c%c %lu %x:%x %x                    %s",
			&from, &to,
			&flags[0], &flags[1], &flags[2], &flags[3],
			&pgoff, &major, &minor, &ino, fpath
		);

		if (fpath[0] == '[')
			continue;

		dump_region(pid, from, to, dumpdir);
	}

cleanup:
	fclose(f_memmap);  
	return success;
}

void dump_region(unsigned int pid, unsigned long start, unsigned long end, char* dumpdir)
{
	FILE* f_mem  = NULL;
	FILE* f_dump = NULL;
	void* buf    = NULL;
	char mempath[PATH_MAX]  = {};
	char dumppath[PATH_MAX] = {};
	snprintf (mempath, PATH_MAX, "/proc/%d/mem", pid);
	snprintf (dumppath, PATH_MAX, "%s/%u.dmp", dumpdir, pid);

	f_mem = fopen(mempath, "r");
	if (!f_mem) {
		fprintf(stderr, "E: Could not open %s for reading\n", mempath);
		goto cleanup;
	}

	f_dump = fopen(dumppath, "ab");
	if (!f_dump) {
		fprintf(stderr, "E: Could not open %s for writting memory contents\n", dumppath);
		goto cleanup;
	}

	size_t bufsize = end - start;
	buf = malloc(bufsize);
	if (!buf) {
		fprintf(stderr, "E: (dump_region) Could not alloc buffer of %zu bytes\n", bufsize);
		goto cleanup;
	}

	fseek(f_mem, start, SEEK_SET);
	size_t rd = fread(buf, 1, bufsize, f_mem);
	fwrite(buf, 1, rd, f_dump);

cleanup:
	fclose(f_mem);
	fclose(f_dump);
	free(buf);
}