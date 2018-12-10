/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
 * @author Xunchao Hu, Heng Yin
 * @date Jan 24 2013
 */

#include <sys/time.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "shared/vmi_callback.h"
#include "utils/Output.h"
#include "vmi_c_wrapper.h"
#include "DECAF_target.h"
#include "y_common.h"
#include "y_apihook.h"
#include <capstone/capstone.h>
//#include "y_inshook.h"
#include "y_api_record.h"


//basic stub for plugins
static plugin_interface_t yhook_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;
static DECAF_Handle blockbegin_handle = DECAF_NULL_HANDLE;

static char targetname[512];
static uint32_t targetpid = -1;
static uint32_t targetcr3 = 0;


static void register_hooks()
{
   Y_api_hook(targetcr3);
   //Y_ins_hook(targetcr3);
	Y_api_record(targetcr3);
}

static void createproc_callback(VMI_Callback_Params* params)
{
    if(targetcr3 != 0) //if we have found the process, return immediately
    	return;

	if (strcasecmp(targetname, params->cp.name) == 0) {
		targetpid = params->cp.pid;
		targetcr3 = params->cp.cr3;		
		DECAF_printf("Process found: pid=%d, cr3=%08x\n", targetpid, targetcr3);
		register_hooks();
	}
}


static void removeproc_callback(VMI_Callback_Params* params)
{
 	//Stop the test when the monitored process terminates
}


static void run_malware(Monitor* mon, const QDict* qdict)
{	
	if ((qdict != NULL) && (qdict_haskey(qdict, "procname"))) {
		strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
	}

	DECAF_printf("run_malware process = %s\n",targetname);
 	targetname[511] = '\0';
}


static int yhook_init(void)
{
	DECAF_output_init(NULL);
	DECAF_printf("Hello World\n");
	//register for process create and process remove events
	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB,
			&createproc_callback, NULL);
	removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB,
			&removeproc_callback, NULL);
	if ((processbegin_handle == DECAF_NULL_HANDLE)
			|| (removeproc_handle == DECAF_NULL_HANDLE)) {
		DECAF_printf("Could not register for the create or remove proc events\n");
	}
	return (0);
}

static void yhook_cleanup(void)
{
	// procmod_Callback_Params params;

	DECAF_printf("Bye world\n");

	if (processbegin_handle != DECAF_NULL_HANDLE) {
		VMI_unregister_callback(VMI_CREATEPROC_CB,
				processbegin_handle);
		processbegin_handle = DECAF_NULL_HANDLE;
	}

	if (removeproc_handle != DECAF_NULL_HANDLE) {
		VMI_unregister_callback(VMI_REMOVEPROC_CB, removeproc_handle);
		removeproc_handle = DECAF_NULL_HANDLE;
	}
	if (blockbegin_handle != DECAF_NULL_HANDLE) {
		DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, blockbegin_handle);
		blockbegin_handle = DECAF_NULL_HANDLE;
	}
	
	//Y_ins_unhook();
}

static mon_cmd_t yhook_term_cmds[] = {
#include "plugin_cmds.h"
		{ NULL, NULL, }, };

plugin_interface_t* init_plugin(void) {
	yhook_interface.mon_cmds = yhook_term_cmds;
	yhook_interface.plugin_cleanup = &yhook_cleanup;

	//initialize the plugin
	yhook_init();
	return (&yhook_interface);
}