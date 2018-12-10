extern "C" {
#include <sys/time.h>
#include "monitor.h"
#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "shared/vmi_callback.h"

#include "utils/Output.h"
#include "vmi_c_wrapper.h"
#include "DECAF_target.h"
#include "shared/tainting/taintcheck_opt.h"
#include "function_map.h"
#include "vmi_callback.h"
	
plugin_interface_t* init_plugin();
//static void Win_OpenFile_Ret(void* opaque);
//static void Win_OpenFile_Call(void* opaque);
//static void createproc_callback(VMI_Callback_Params* params);
//static void behaviormon_cleanup();
}

#include <iostream>
#include <cstdlib>
#include <map>
#include <string>
using namespace std;

static plugin_interface_t behavior_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
DECAF_Handle handle_write_taint_mem = DECAF_NULL_HANDLE;
DECAF_Handle handle_read_taint_mem = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_end_cb = DECAF_NULL_HANDLE;
map<uint32_t, string> file_map;
bool taint_file = true;
string target_file = "data.txt";
FILE * logs = DECAF_NULL_HANDLE;

uint32_t guest_wstrncpy(char *buf, size_t maxlen, gva_t vaddr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
    	DECAF_read_mem(NULL, vaddr+2*i, 2, &buf[i]);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

uint32_t check_virtmem(gva_t vaddr, uint32_t size)
{
	uint8_t* taint_flag = new uint8_t[size];
	int ret = taintcheck_check_virtmem(vaddr, size, taint_flag);
	// if(ret != 0) DECAF_printf("taintcheck_check_virtmem failed.\n");

	int taint_bytes = 0, i;
	for(i = 0; i < size; i++) if(taint_flag[i]) taint_bytes += 1;
	delete[] taint_flag;
	
	return taint_bytes;
}

//----------- Kernel32.dll OpenFile --------------
// HFILE WINAPI OpenFile(_In_  LPCSTR lpFileName, _Out_ LPOFSTRUCT lpReOpenBuff, _In_  UINT uStyle);

struct OpenFile_params{
	uint32_t params[4];
	DECAF_Handle openfile_handle;
};

static void Win_OpenFile_Ret(void* opaque)
{
	OpenFile_params* params = (OpenFile_params*)opaque;
	char tmp[256];
	DECAF_read_mem(NULL, params->params[1], 256, tmp);
	string lpFileName(tmp);
	uint32_t hfile = cpu_single_env->regs[R_EAX];

	if(hfile)
	{
		file_map[hfile] = lpFileName;
		//DECAF_printf("OpenFile %s, handle: %d\n", lpFileName.c_str(), hfile);
		//if(lpFileName.rfind(target_file) == lpFileName.length() - target_file.length()) DECAF_printf("Target File open monitored!\n");
	}

	hookapi_remove_hook(params->openfile_handle);
	delete params;
}

static void Win_OpenFile_Call(void* opaque)
{
	OpenFile_params* params = new OpenFile_params;
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, params);
	params->openfile_handle = hookapi_hook_return(params->params[0], Win_OpenFile_Ret, params, sizeof(OpenFile_params));
}

// ---------------------------- Kernel32.dll CreateFile --------------------
/*
HANDLE WINAPI CreateFile(
  _In_     LPCTSTR               lpFileName,
  _In_     DWORD                 dwDesiredAccess,
  _In_     DWORD                 dwShareMode,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_     DWORD                 dwCreationDisposition,
  _In_     DWORD                 dwFlagsAndAttributes,
  _In_opt_ HANDLE                hTemplateFile
);
*/
struct CreateFile_params
{
	uint32_t stack[8];
	DECAF_Handle createfile_handle;
};

static void Win_CreateFileW_Ret(void* params)
{
	CreateFile_params* p = (CreateFile_params*) params;
	char tmp[256];
	//DECAF_read_mem(NULL, p->stack[1], 256, FileName);
	guest_wstrncpy(tmp, 256, p->stack[1]);
	string FileName(tmp);

	uint32_t file_handle = cpu_single_env->regs[R_EAX];
	if(file_handle)
	{
		file_map[file_handle] = FileName;
		//DECAF_printf("CreateFile %s, handle: %d\n", FileName.c_str(), file_handle);
		//if(FileName.rfind(target_file) == FileName.length() - target_file.length()) DECAF_printf("Target File open monitored!\n");
	}

	hookapi_remove_hook(p->createfile_handle);
	delete p;
}

static void Win_CreateFileW_Call(void* opaque)
{
	CreateFile_params* params = new CreateFile_params;
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 8*4, params);

	params->createfile_handle = hookapi_hook_return(params->stack[0], Win_CreateFileW_Ret, params, sizeof(CreateFile_params));
}

static void Win_CreateFileA_Ret(void* params)
{
	CreateFile_params* p = (CreateFile_params*) params;
	char tmp[256];
	DECAF_read_mem(NULL, p->stack[1], 256, tmp);
	string FileName(tmp);

	uint32_t file_handle = cpu_single_env->regs[R_EAX];
	if(file_handle)
	{
		file_map[file_handle] = FileName;
		//DECAF_printf("CreateFile %s, handle: %d\n", FileName.c_str(), file_handle);
		// if(FileName.rfind(target_file) == FileName.length() - target_file.length()) DECAF_printf("Target File open monitored!\n");
	}

	hookapi_remove_hook(p->createfile_handle);
	delete p;
}

static void Win_CreateFileA_Call(void* opaque)
{
	CreateFile_params* params = new CreateFile_params;
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 8*4, params);

	params->createfile_handle = hookapi_hook_return(params->stack[0], Win_CreateFileA_Ret, params, sizeof(CreateFile_params));
}
// ---------- Kernel32.dll ReadFile -------------
/*
BOOL WINAPI ReadFile(
  _In_        HANDLE       hFile,
  _Out_       LPVOID       lpBuffer,
  _In_        DWORD        nNumberOfBytesToRead,
  _Out_opt_   LPDWORD      lpNumberOfBytesRead,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
);
*/

struct ReadFile_params
{
	uint32_t stack[6];
	DECAF_Handle readfile_handle;
};

static void Win_ReadFile_Ret(void* params)
{
	ReadFile_params* p = (ReadFile_params*)params;
	uint32_t hfile = p->stack[1];
	// DECAF_printf("ReadFile: read_handle: %d\n", p->stack[1]);
	string filename = file_map[hfile];
	uint32_t bytes_read;
	DECAF_read_mem(NULL, p->stack[4], 4, &bytes_read);

	// DECAF_printf("ReadFile: filename %s %d bytes.\n", filename.c_str(), bytes_read);

	if(taint_file)
	{
		if(filename.rfind(target_file) == filename.length() - target_file.length())
		{
			uint8_t * taint_flag = new uint8_t[bytes_read];
			memset((void*)taint_flag, 0xff, bytes_read);
			taintcheck_taint_virtmem(p->stack[2], bytes_read, taint_flag);
			delete taint_flag;

			// DECAF_printf("ReadFile: read content tainted %d bytes.\n", bytes_read);
		}
	}

	hookapi_remove_hook(p->readfile_handle);
	delete p;
}

static void Win_ReadFile_Call(void* opaque)
{
	ReadFile_params* param = new ReadFile_params;
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6*4, param);

	param->readfile_handle = hookapi_hook_return(param->stack[0], Win_ReadFile_Ret, param, sizeof(ReadFile_params));
}

// ------------------------ Kernel32.dll WriteFile --------------------

/*BOOL WINAPI WriteFile(
  _In_        HANDLE       hFile,
  _In_        LPCVOID      lpBuffer,
  _In_        DWORD        nNumberOfBytesToWrite,
  _Out_opt_   LPDWORD      lpNumberOfBytesWritten,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
);*/
struct WriteFile_params{
	uint32_t stack[6];
	DECAF_Handle writefile_handle;
};

static void Win_WriteFile_Ret(void* params)
{
	WriteFile_params* p = (WriteFile_params*)params;
	uint32_t hfile = p->stack[1];
	string filename = file_map[hfile];
	//DECAF_printf("WriteFile: handle %d, filename %s, write buffer %p, write %d bytes.\n", hfile, filename.c_str(), 
	//	p->stack[2], p->stack[3]);
	
	if(taint_file)
	{
		//uint32_t bytes_write;
		//DECAF_read_mem(NULL, p->stack[4], 4, &bytes_write);
		int taint_bytes = check_virtmem(p->stack[2], p->stack[3]); //bytes_write);

		uint32_t eip= DECAF_getPC(cpu_single_env);
		uint32_t cr3= DECAF_getPGD(cpu_single_env);
		char name[128];
		tmodinfo_t  dm;// (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
		if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
		{
			strcpy(name, "<None>");
			bzero(&dm, sizeof(dm));
		}

		// if(taint_bytes) DECAF_printf("Process %s WriteFile: filename=%s write %d bytes tainted memory!\n", 
		//	name, filename.c_str(), taint_bytes);
	}
	hookapi_remove_hook(p->writefile_handle);
	delete p;
}

static void Win_WriteFile_Call(void* opaque)
{
	WriteFile_params* params = new WriteFile_params;
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6*4, params);

	params->writefile_handle = hookapi_hook_return(params->stack[0], Win_WriteFile_Ret, params, sizeof(WriteFile_params));
}

// --------------------- Kernel32.dll DeleteFile ------------------
// BOOL WINAPI DeleteFile( _In_ LPCTSTR lpFileName );
struct DeleteFile_params{
	uint32_t stack[2];
	DECAF_Handle deletefile_handle;
};

static void Win_DeleteFile_Ret(void* params)
{
	DeleteFile_params* p = (DeleteFile_params*)params;
	wchar_t filename[256];
	DECAF_read_mem(NULL, p->stack[1], 512, filename);

	//DECAF_printf("DeleteFile: filename %s.\n", filename);
	
	hookapi_remove_hook(p->deletefile_handle);
	delete p;
}

static void Win_DeleteFile_Call(void* opaque)
{
	DeleteFile_params* params = new DeleteFile_params;
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, params);

	params->deletefile_handle = hookapi_hook_return(params->stack[0], Win_DeleteFile_Ret, params, sizeof(DeleteFile_params));
}

// ---------------------- Ws2_32.dll sento ------------
/*
int sendto(
  _In_       SOCKET                s,
  _In_ const char                  *buf,
  _In_       int                   len,
  _In_       int                   flags,
  _In_       const struct sockaddr *to,
  _In_       int                   tolen
);
*/

struct sendto_params{
	uint32_t stack[7];
	DECAF_Handle sendto_handle;
};

static void Win_sendto_Ret(void* params)
{
	sendto_params* p = (sendto_params*)params;
	if(taint_file)
	{
		uint8_t* taint_flag = new uint8_t[p->stack[3]];
		taintcheck_check_virtmem(p->stack[2], p->stack[3], taint_flag);

		int taint_bytes = 0;
		for(int i = 0; i < p->stack[3]; i++) if(taint_flag[i]) taint_bytes += 1;
		delete[] taint_flag;

		uint32_t eip= DECAF_getPC(cpu_single_env);
		uint32_t cr3= DECAF_getPGD(cpu_single_env);
		char name[128];
		tmodinfo_t  dm;// (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
		if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
		{
			strcpy(name, "<None>");
			bzero(&dm, sizeof(dm));
		}

		// if(taint_bytes) DECAF_printf("Process %s in function sendto: send %d tainted bytes!\n",name, taint_bytes);
	}
	delete p;
}

static void Win_sendto_Call(void* opaque)
{
	sendto_params* params = new sendto_params;
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 7*4, params);
	DECAF_printf("sendto: hooked.\n");

	params->sendto_handle = hookapi_hook_return(params->stack[0], Win_sendto_Ret, params, sizeof(sendto_params));
}

// ---------------------- Ws2_32.dll sento ------------
/*
int send(
  _In_       SOCKET s,
  _In_ const char   *buf,
  _In_       int    len,
  _In_       int    flags
);
*/
struct send_params{
	uint32_t stack[5];
	DECAF_Handle send_handle;
};

static void Win_send_Ret(void* params)
{
	send_params* p = (send_params*)params;
	if(taint_file)
	{
		uint8_t* taint_flag = new uint8_t[p->stack[3]];
		int ret = taintcheck_check_virtmem(p->stack[2], p->stack[3], taint_flag);
		//if(ret == 0) DECAF_printf("WriteFile: write buffer check success.\n");
		//else{
		//	DECAF_printf("WriteFile: write buffer check failed.\n");
		//	delete p;
		//return;	
		//}

		int taint_bytes = 0;
		for(int i = 0; i < p->stack[3]; i++) if(taint_flag[i]) taint_bytes += 1;

		delete taint_flag;

		uint32_t eip= DECAF_getPC(cpu_single_env);
		uint32_t cr3= DECAF_getPGD(cpu_single_env);
		char name[128];
		tmodinfo_t  dm;// (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
		if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
		{
			strcpy(name, "<None>");
			bzero(&dm, sizeof(dm));
		}

		//if(taint_bytes) DECAF_printf("Process %s in function send: send %d tainted bytes!\n",name, taint_bytes);
	}
	delete p;
}

static void Win_send_Call(void* opaque)
{
	send_params* params = new send_params;
	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 5*4, params);
	//DECAF_printf("send: hooked.\n");
	params->send_handle = hookapi_hook_return(params->stack[0], Win_send_Ret, params, sizeof(send_params));
}

static void createproc_callback(VMI_Callback_Params* params)
{
	// ("createproc: %s\n", params->cp.name);
	hookapi_hook_function_byname("Kernel32.dll", "OpenFile", 1, params->cp.cr3, Win_OpenFile_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "CreateFileW", 1, params->cp.cr3, Win_CreateFileW_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "CreateFileA", 1, params->cp.cr3, Win_CreateFileA_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "ReadFile", 1, params->cp.cr3, Win_ReadFile_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "WriteFile", 1, params->cp.cr3, Win_WriteFile_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "DeleteFileW", 1, params->cp.cr3, Win_DeleteFile_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "DeleteFileA", 1, params->cp.cr3, Win_DeleteFile_Call, NULL, 0);
	hookapi_hook_function_byname("Ws2_32.dll", "sendto", 1, params->cp.cr3, Win_sendto_Call, NULL, 0);
	hookapi_hook_function_byname("Ws2_32.dll", "send", 1, params->cp.cr3, Win_send_Call, NULL, 0);
}

static void behaviormon_cleanup()
{
	if (processbegin_handle != DECAF_NULL_HANDLE) 
	{
		VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);
		processbegin_handle = DECAF_NULL_HANDLE;
	}
	//if(handle_read_taint_mem)
	//		DECAF_unregister_callback(DECAF_READ_TAINTMEM_CB,handle_read_taint_mem);
	//if(handle_write_taint_mem)
	//		DECAF_unregister_callback(DECAF_WRITE_TAINTMEM_CB,handle_write_taint_mem);
	//if(handle_block_end_cb)
	//		DECAF_unregisterOptimizedBlockEndCallback(handle_block_end_cb);

	//handle_read_taint_mem = DECAF_NULL_HANDLE;
	//handle_write_taint_mem = DECAF_NULL_HANDLE;
	//handle_block_end_cb = DECAF_NULL_HANDLE;
}

#define MAX_STACK_SIZE 5000
char modname_t[512];
char func_name_t[512];
uint32_t sys_call_ret_stack[MAX_STACK_SIZE];
uint32_t sys_call_entry_stack[MAX_STACK_SIZE];
uint32_t cr3_stack[MAX_STACK_SIZE];
uint32_t stack_top = 0;

void check_call(DECAF_Callback_Params *param)
{
	CPUState *env=param->be.env;
	if(env == NULL)
	return;
	target_ulong pc = param->be.next_pc;
	target_ulong cr3 = DECAF_getPGD(env) ;

	if(stack_top == MAX_STACK_SIZE)
	{
     //if the stack reaches to the max size, we ignore the data from stack bottom to MAX_STACK_SIZE/10
		memcpy(sys_call_ret_stack,&sys_call_ret_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(sys_call_entry_stack,&sys_call_entry_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(cr3_stack,&cr3_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		stack_top = MAX_STACK_SIZE-MAX_STACK_SIZE/10;
		return;
	}
	if(funcmap_get_name_c(pc, cr3, modname_t, func_name_t))
	{
		DECAF_read_mem(env,env->regs[R_ESP],4,&sys_call_ret_stack[stack_top]);
		sys_call_entry_stack[stack_top] = pc;
		cr3_stack[stack_top] = cr3;
		stack_top++;
	}
}

void check_ret(DECAF_Callback_Params *param)
{
	if(!stack_top)
		return;
	if(param->be.next_pc == sys_call_ret_stack[stack_top-1])
	{
		stack_top--;
	}
}

void do_block_end_cb(DECAF_Callback_Params *param)
{
	unsigned char insn_buf[2];
	int is_call = 0, is_ret = 0;
	int b;
	DECAF_read_mem(param->be.env,param->be.cur_pc,sizeof(char)*2,insn_buf);

	switch(insn_buf[0]) {
		case 0x9a:
		case 0xe8:
		is_call = 1;
		break;
		case 0xff:
		b = (insn_buf[1]>>3) & 7;
		if(b==2 || b==3)
		is_call = 1;
		break;

		case 0xc2:
		case 0xc3:
		case 0xca:
		case 0xcb:
		is_ret = 1;
		break;
		default: break;
	}

	/*
	 * Handle both the call and the return
	 */
	if (is_call)
	check_call(param);
	else if (is_ret)
	check_ret(param);
}

void do_read_taint_mem(DECAF_Callback_Params *param)
{
	uint32_t eip=DECAF_getPC(cpu_single_env);
	uint32_t cr3= DECAF_getPGD(cpu_single_env);
	char name[128];
	tmodinfo_t dm;// (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
	if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
	{
		strcpy(name, "<None>");
		bzero(&dm, sizeof(dm));
	}
	if(stack_top)
	{
		if(cr3 == cr3_stack[stack_top-1])
			funcmap_get_name_c(sys_call_entry_stack[stack_top-1], cr3, modname_t, func_name_t);
		else {
			memset(modname_t, 0, 512);
			memset(func_name_t, 0, 512);
		}
	}
	else {
		memset(modname_t, 0, 512);
		memset(func_name_t, 0, 512);
	}
	if(param->rt.size <=4)
		fprintf(logs,"%s   \t 0 \t 0x%08x \t\t 0x%08x \t %d      0x%08x  0x%08x %15s    \t%s\t%s\n",
			name, param->rt.vaddr, param->rt.paddr, param->rt.size,*((uint32_t *)param->rt.taint_info), eip, dm.name,modname_t,func_name_t);
	else
		fprintf(logs,"%s   \t 0 \t 0x%08x \t\t 0x%08x \t %d      0x%16x  0x%08x %15s     \t%s\t%s\n",
					name, param->rt.vaddr, param->rt.paddr, param->rt.size,*((uint32_t *)param->rt.taint_info), eip, dm.name,  modname_t,func_name_t);
}


void do_write_taint_mem(DECAF_Callback_Params *param)
{
	uint32_t eip= DECAF_getPC(cpu_single_env);
	uint32_t cr3= DECAF_getPGD(cpu_single_env);
	char name[128];
	tmodinfo_t  dm;// (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
	if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
	{
		strcpy(name, "<None>");
		bzero(&dm, sizeof(dm));
	}

	if(stack_top)
	{
		if(cr3 == cr3_stack[stack_top-1])
			funcmap_get_name_c(sys_call_entry_stack[stack_top-1], cr3, modname_t, func_name_t);
		else {
			memset(modname_t, 0, 512);
			memset(func_name_t, 0, 512);
		}
	}
	else {
		memset(modname_t, 0, 512);
		memset(func_name_t, 0, 512);
	}

	//fprintf(keylogger_log,"%s    1  0x%08x  0x%08x  %d   0x%08x %s   0x%08x  %d    %s\n",
	//		name, param->rt.vaddr, param->rt.paddr, param->rt.size, eip, dm->name, dm->base, dm->size, dm->fullname);
	if(param->rt.size <=4)
			fprintf(logs,"%s   \t 1 \t 0x%08x \t\t 0x%08x \t %d      0x%08x  0x%08x %15s   \t%s\t%s\n",
				name, param->rt.vaddr, param->rt.paddr, param->rt.size,*((uint32_t *)param->rt.taint_info), eip, dm.name,modname_t,func_name_t);
		else
			fprintf(logs,"%s   \t 1 \t 0x%08x \t\t 0x%08x \t %d      0x%16x  0x%08x %15s    \t%s\t%s\n",
						name, param->rt.vaddr, param->rt.paddr, param->rt.size,*((uint32_t *)param->rt.taint_info), eip, dm.name, modname_t,func_name_t);
}

void do_set_logfile(Monitor *mon, const QDict *qdict)
{
	
}


static mon_cmd_t behaviormon_cmds[] = {
#include "plugin_cmds.h"
		{ NULL, NULL, }, };

plugin_interface_t* init_plugin()
{
	behavior_interface.mon_cmds = behaviormon_cmds;
	behavior_interface.plugin_cleanup = &behaviormon_cleanup;

	logs = fopen("logfile", "w");
	if(!logs)
	{
		DECAF_printf("the %s can not be open or created !!", logs);
		return &behavior_interface;
	}
	
	//fprintf(logs, "Process Read(0)/Write(1) vaddOfTaintedMem   paddrOfTaintedMem    Size   "
	//		"TaintInfo   CurEIP \t ModuleName   \t CallerModuleName \t CallerSystemCall\n");

	//if(!handle_read_taint_mem)
		//handle_read_taint_mem = DECAF_register_callback(DECAF_READ_TAINTMEM_CB,do_read_taint_mem,NULL);
	//if(!handle_write_taint_mem)
		//handle_write_taint_mem = DECAF_register_callback(DECAF_WRITE_TAINTMEM_CB,do_write_taint_mem,NULL);
	//if(!handle_block_end_cb)
		//handle_block_end_cb =  DECAF_registerOptimizedBlockEndCallback(do_block_end_cb, NULL, INV_ADDR, INV_ADDR);

	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &createproc_callback, NULL);
	
	return &behavior_interface;
}
