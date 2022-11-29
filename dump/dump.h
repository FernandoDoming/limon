#pragma once

bool dump_pid(unsigned int pid, char* dumpdir);
void dump_region(unsigned int pid, unsigned long start, unsigned long end, char* dumpdir);