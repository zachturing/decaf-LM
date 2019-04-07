#ifndef _STRINGSEARCH_HANDLE_H_
#define _STRINGSEARCH_HANDLE_H_

#define MAX_STRINGS 100
#define MAX_CALLERS 128
#define MAX_STRLEN  1024

#define MAX_SEARCH_LEN 4  //one page size: 4k = 4096bytes
#define STRING_LEN     9

#define PROC_NUM 3


const char procname[PROC_NUM][MAX_STRLEN] = {
	{"httpd.exe"},
	{"IEXPLORE.EXE"},
	{"firefox.exe"}
};


void stringsearch_cleanup();
int mem_callback(void *buf, int size, bool is_write);
bool parse_file(const char* stringsfile);
void do_mem_read_cb(DECAF_Callback_Params *param);
void do_mem_write_cb(DECAF_Callback_Params *param);

#endif


