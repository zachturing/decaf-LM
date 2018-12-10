
//命令处理函数

#ifdef __cplusplus
extern "C"
{
#endif 
#include <sys/time.h>
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include "hookapi.h"
#include "shared/vmi_callback.h"
#include "vmi_c_wrapper.h"
#include "shared/tainting/taintcheck_opt.h"
#include "function_map.h"
#include "DECAF_types.h"
#include "config.h"

#ifdef __cplusplus
}
#endif

#include "nic_handle.h"
#include "keylogger_handle.h"
#include "stringsearch_handle.h"

extern char targetname[512];
extern FILE *keylogger_log;
extern FILE *nic_log;
extern FILE *stringsearch_log;

extern int taint_key_enabled;
extern DECAF_Handle keystroke_cb_handle;
extern DECAF_Handle handle_write_taint_mem;
extern DECAF_Handle handle_read_taint_mem;
extern DECAF_Handle handle_block_end_cb;

extern DECAF_Handle nic_rec_cb_handle;
extern DECAF_Handle nic_send_cb_handle;

extern DECAF_Handle mem_read_handle;
extern DECAF_Handle mem_write_handle;

void do_monitor_proc(Monitor* mon, const QDict* qdict)
{
	if ((qdict != NULL) && (qdict_haskey(qdict, "procname"))) 
	{
		strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
	}
	targetname[511] = '\0';
}

void do_set_logfile1(Monitor *mon, const QDict *qdict)
{
	const char *logfile_t = qdict_get_str(qdict, "logfile");
	DECAF_printf("%s 1\n", logfile_t);
}

void do_set_logfile2(Monitor *mon, const QDict *qdict)
{
	const char *logfile_t = qdict_get_str(qdict, "logfile");
	DECAF_printf("%s 2\n", logfile_t);
}


void do_enable_nic(Monitor *mon)
{
	DECAF_printf("do_enable_nic.\n");
	nic_log = fopen("nic_log", "w");
	if(!nic_log)
	{
		DECAF_printf("the nic_log can not be open or created !!.\n");
		return;
	}

	/*
     * 注册网络发送/接收回调函数
     */
	nic_rec_cb_handle   = DECAF_register_callback(DECAF_NIC_REC_CB , tracing_nic_recv, NULL);
	nic_send_cb_handle  = DECAF_register_callback(DECAF_NIC_SEND_CB, tracing_nic_send, NULL);
	if ((DECAF_NULL_HANDLE == nic_rec_cb_handle) || (DECAF_NULL_HANDLE == nic_send_cb_handle)) 
	{
		DECAF_printf("Could not register for the rec or send events\n");
	}
}

void do_disable_nic(Monitor *mon)
{
	DECAF_printf("do_disable_nic.\n");

	nic_cleanup();
}

//keylogger相关处理函数
void do_enable_keylogger_check( Monitor *mon, const QDict *qdict)
{
	DECAF_printf("do_enable_keylogger_check.\n");  //指定日志文件
	const char *tracefile_t = qdict_get_str(qdict, "tracefile");
	keylogger_log= fopen(tracefile_t,"w");   
	if(!keylogger_log)
	{
		DECAF_printf("the %s can not be open or created !!",tracefile_t);
		return;
	}

	fprintf(keylogger_log,"Process Read(0)/Write(1) vaddOfTaintedMem   paddrOfTaintedMem    Size   "
			"TaintInfo   CurEIP \t ModuleName   \t CallerModuleName \t CallerSystemCall\n");
	if(!handle_read_taint_mem)   
	{
		handle_read_taint_mem = DECAF_register_callback(DECAF_READ_TAINTMEM_CB, do_read_taint_mem, NULL);
	}
	if(!handle_write_taint_mem)
	{
		handle_write_taint_mem = DECAF_register_callback(DECAF_WRITE_TAINTMEM_CB, do_write_taint_mem, NULL);
	}
	if(!handle_block_end_cb)
	{
		handle_block_end_cb =  DECAF_registerOptimizedBlockEndCallback(do_block_end_cb, NULL, INV_ADDR, INV_ADDR);
	}
	fflush(keylogger_log);
}

void do_disable_keylogger_check( Monitor *mon, const QDict *qdict)
{
	DECAF_printf("do_disable_keylogger_check.\n");
	keylogger_cleanup();   //只注销keylogger这部分的资源
	DECAF_printf("disable taintmodule check successfully.\n");
}


void do_taint_sendkey(Monitor *mon, const QDict *qdict)
{
	// Set the origin and offset for the callback
	if(qdict_haskey(qdict, "key"))
	{
	 	taint_key_enabled=1;
		if(!keystroke_cb_handle) //register keystroke callback
		{
			keystroke_cb_handle = DECAF_register_callback(DECAF_KEYSTROKE_CB,
					tracing_send_keystroke, &taint_key_enabled);
		}	
		do_send_key(qdict_get_str(qdict, "key"));// Send the key
	}
	else
	{
		monitor_printf(mon, "taint_sendkey command is malformed\n");
	}    
}

void do_enable_search_file( Monitor *mon, const QDict *qdict)
{
	DECAF_printf("do_enable_search_file.\n");
	const char *search_file = qdict_get_str(qdict, "filename");
	parse_file(search_file);  	
	DECAF_printf("%s\n", search_file);
	
	stringsearch_log = fopen("stringsearch.log", "w");
	if(NULL == stringsearch_log)
	{
		DECAF_printf("The %s can not be open or created!!!\n", search_file);
		return;
	}

	mem_read_handle  = DECAF_register_callback(DECAF_MEM_READ_CB,  do_mem_read_cb,  NULL);
	mem_write_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB, do_mem_write_cb, NULL);
	
	if((DECAF_NULL_HANDLE == mem_read_handle) || (DECAF_NULL_HANDLE == mem_write_handle))
	{
		DECAF_printf("Could not register for the write/read mem events\n");
	}
}

void do_disable_search_file( Monitor *mon, const QDict *qdict)
{
	DECAF_printf("do_disable_search_file.\n");
	stringsearch_cleanup();
}