extern "C"
{
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
}

extern "C" { 
plugin_interface_t* init_plugin(void); 
void plugin_cleanup();

static plugin_interface_t plugin_interface;
}

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <vector>
#include <algorithm>

#include "nic_handle.h"			 //网络回调处理函数
#include "cmd_handle.h"  		 //命令处理函数
#include "keylogger_handle.h"    //keylogger相关处理函数
#include "stringsearch_handle.h" 
#include "apihook_file_handle.h" //文件操作相关API hook处理函数
using namespace std;

DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
DECAF_Handle removeproc_handle   = DECAF_NULL_HANDLE;

//string search
DECAF_Handle mem_read_handle  = DECAF_NULL_HANDLE;
DECAF_Handle mem_write_handle = DECAF_NULL_HANDLE;

//nic
DECAF_Handle nic_rec_cb_handle   = DECAF_NULL_HANDLE;
DECAF_Handle nic_send_cb_handle  = DECAF_NULL_HANDLE;

//keylogger
DECAF_Handle keystroke_cb_handle    = DECAF_NULL_HANDLE;
DECAF_Handle handle_write_taint_mem = DECAF_NULL_HANDLE;
DECAF_Handle handle_read_taint_mem  = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_end_cb    = DECAF_NULL_HANDLE;

static uint32_t targetpid = -1;
static uint32_t targetcr3 = 0;

char targetname[512];

map<uint32_t, string> file_map;		//在文件句柄和文件名之间建立对应关系
vector<string> vTargetFile;  		//存放要监控的文件名
string target_file = "data.txt";

//存放日志文件的文件指针
FILE *keylogger_log    = DECAF_NULL_HANDLE;
FILE *nic_log          = DECAF_NULL_HANDLE;
FILE *stringsearch_log = DECAF_NULL_HANDLE;
FILE *hook_log         = DECAF_NULL_HANDLE;

static void register_hooks(VMI_Callback_Params* params)
{
	hookapi_hook_function_byname("Kernel32.dll", "OpenFile",    1, params->cp.cr3, Win_OpenFile_Call,    NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "CreateFileW", 1, params->cp.cr3, Win_CreateFileW_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "CreateFileA", 1, params->cp.cr3, Win_CreateFileA_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "ReadFile",    1, params->cp.cr3, Win_ReadFile_Call,    NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "WriteFile",   1, params->cp.cr3, Win_WriteFile_Call,   NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "DeleteFileW", 1, params->cp.cr3, Win_DeleteFileW_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "DeleteFileA", 1, params->cp.cr3, Win_DeleteFileA_Call, NULL, 0);

	//hookapi_hook_function_byname("Ws2_32.dll", "sendto", 1, params->cp.cr3, Win_sendto_Call, NULL, 0);
	//hookapi_hook_function_byname("Ws2_32.dll", "send",   1, params->cp.cr3, Win_send_Call,   NULL, 0);

	hookapi_hook_function_byname("Kernel32.dll", "MoveFileA", 1, params->cp.cr3, Win_MoveFileA_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "MoveFileW", 1, params->cp.cr3, Win_MoveFileW_Call, NULL, 0);

	hookapi_hook_function_byname("Kernel32.dll", "MoveFileExA", 1, params->cp.cr3, Win_MoveFileExA_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "MoveFileExW", 1, params->cp.cr3, Win_MoveFileExW_Call, NULL, 0);

	hookapi_hook_function_byname("Kernel32.dll", "MoveFileWithProgressA", 1, params->cp.cr3, Win_MoveFileWithProgressA_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "MoveFileWithProgressW", 1, params->cp.cr3, Win_MoveFileWithProgressW_Call, NULL, 0);

	hookapi_hook_function_byname("Kernel32.dll", "MoveFileTransactedA", 1, params->cp.cr3, Win_MoveFileTransactedA_Call, NULL, 0);
	hookapi_hook_function_byname("Kernel32.dll", "MoveFileTransactedW", 1, params->cp.cr3, Win_MoveFileTransactedW_Call, NULL, 0);
}

static void createproc_callback(VMI_Callback_Params* params)
{
	if (strcasecmp(targetname, params->cp.name) == 0) 
	{
		targetpid = params->cp.pid; //获取目标进程的pid和cr3寄存器的值
		targetcr3 = params->cp.cr3;
		//DECAF_printf("Process found: pid=%d, cr3=%08x\n", targetpid, targetcr3);
	}
	register_hooks(params);  //注册需要hook的函数
}

static void removeproc_callback(VMI_Callback_Params* params)
{
	//Stop the test when the monitored process terminates
}

void plugin_cleanup()
{
	DECAF_printf("All monitor file:\n");  

	//输出所有的被监控文件的文件名
	for(vector<string>::iterator it = vTargetFile.begin(); it != vTargetFile.end(); ++it)
	{
		DECAF_printf("%s\n", it->c_str());
	}
	DECAF_printf("=========================================\n");

	keylogger_cleanup();  //注销keylogger相关资源

	nic_cleanup();		  //注销nic相关资源

	stringsearch_cleanup();  //

	if(hook_log)
	{
		fclose(hook_log);
		hook_log = NULL;
	}

	if(processbegin_handle != DECAF_NULL_HANDLE)
	{
		VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);
		processbegin_handle = DECAF_NULL_HANDLE;
	}
	
	if(removeproc_handle != DECAF_NULL_HANDLE)
	{
		VMI_unregister_callback(VMI_REMOVEPROC_CB, removeproc_handle);
		removeproc_handle = DECAF_NULL_HANDLE;
	}

 	DECAF_printf("Bye Bye.\n");
}

//定义插件命令
static mon_cmd_t plugin_term_cmds[] = {
	#include "plugin_cmds.h"
  	{NULL, NULL, },
};

static int my_plugin_init(void)
{
	DECAF_output_init(NULL);
	DECAF_printf("Hello World\n");
	hook_log = fopen("hook_log", "w");
	if(!hook_log)
	{
		DECAF_printf("the hook_log can not be open or created !!.\n");
		return 0;
	}
	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, createproc_callback, NULL);
	removeproc_handle   = VMI_register_callback(VMI_REMOVEPROC_CB, removeproc_callback, NULL);
	
	if ((DECAF_NULL_HANDLE == processbegin_handle) || (DECAF_NULL_HANDLE == removeproc_handle)) 
	{
		DECAF_printf("Could not register for the create or remove proc events\n");
	}
	return (0);
}

plugin_interface_t* init_plugin(void) 
{
	plugin_interface.mon_cmds = plugin_term_cmds;
	plugin_interface.plugin_cleanup = &plugin_cleanup;

	my_plugin_init();
	vTargetFile.push_back(target_file);
	PrintInfo();
	return (&plugin_interface);
}

///////////////////////////////////////////////////////////////////////////
void Win_sendto_Ret(void* params)
{
	
}

void Win_sendto_Call(void* opaque)
{
	//DECAF_printf("Win_sendto_Call.\n");
}

void Win_send_Ret(void* params)
{	

}

void Win_send_Call(void* opaque)
{
	//DECAF_printf("Win_send_Call.\n");
}

///////////////////////////////////////////////////////////////////////

