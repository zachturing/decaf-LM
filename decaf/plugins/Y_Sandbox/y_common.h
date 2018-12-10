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


#ifndef Y_COMMON_H
#define Y_COMMON_H

#include <sys/time.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "DECAF_callback.h"
#include "shared/vmi_callback.h"
#include "utils/Output.h"
#include "vmi_c_wrapper.h"
#include "DECAF_target.h"
#include <string.h>
#include <time.h>


typedef struct{
    uint32_t call_stack[64];
    DECAF_Handle hook_handle;  
}Y_Func_Stack;


static void Y_print_api_info(char* dll_name,char* api_name,int entry){
	time_t now;    
	time(&now);
	struct tm* timenow = localtime(&now);

	if(entry==1)DECAF_printf("%s---%s---%s--- Entry\n", asctime(timenow),dll_name,api_name);
	else DECAF_printf("%s---%s---%s--- Exit\n", asctime(timenow),dll_name,api_name);
}

static char* spec_file_list[]={
		//vb
		"C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys",
		"C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys",
		"C:\\WINDOWS\\system32\\drivers\\VBoxSF.sys",
		"C:\\WINDOWS\\system32\\drivers\\VBoxVideo.sys",
		"C:\\WINDOWS\\system32\\vboxdisp.dll",
		"C:\\WINDOWS\\system32\\vboxhook.dll",
		"C:\\\\WINDOWS\\system32\\vboxmrxnp.dll",
		"C:\\WINDOWS\\system32\\vboxogl.dll",
		"C:\\WINDOWS\\system32\\vboxoglarrayspu.dll",
		"C:\\WINDOWS\\system32\\vboxoglcrutil.dll",
		"C:\\WINDOWS\\system32\\vboxoglerrorspu.dll",
		"C:\\WINDOWS\\system32\\vboxoglfeedbackspu.dll",
		"C:\\WINDOWS\\system32\\vboxoglpackspu.dll",
		"C:\\WINDOWS\\system32\\vboxoglpassthroughspu.dll",
		"C:\\WINDOWS\\system32\\vboxservice.exe",
		"C:\\WINDOWS\\system32\\vboxtray.exe",
		"C:\\WINDOWS\\system32\\VBoxControl.exe",
		"C:\\program files\\oracle\\virtualbox guest additions\\",

		//vmware
		"C:\\WINDOWS\\system32\\vm3dgl64.dll",
		"C:\\WINDOWS\\system32\\vm3dgl.dll",
		"C:\\WINDOWS\\system32\\vm3dum64.dll",
		"C:\\WINDOWS\\system32\\vm3dum.dll",
		"C:\\WINDOWS\\system32\\VmbuxCoinstaller.dll",
		"C:\\WINDOWS\\system32\\vmGuestLib.dll",
		"C:\\WINDOWS\\system32\\vmGuestLibJava.dll",
		"C:\\WINDOWS\\system32\\vmhgfs.dll",
		"C:\\WINDOWS\\system32\\vmwogl32.dll",
		"C:\\WINDOWS\\system32\\vmmreg32.dll",
		"C:\\WINDOWS\\system32\\vmx_fb.dll",
		"C:\\WINDOWS\\system32\\vmx_mode.dll",
		"C:\\WINDOWS\\system32\\VMUpgradeAtShutdownWXP.dll"
};

static char * spec_reg_list[]={
		//vmware
		"SOFTWARE\\Clients\\StartMenuInternet\\VMWAREHOSTOPEN.EXE",
		"SOFTWARE\\VMware, Inc.\\VMware Tools",
		"SOFTWARE\\Microsoft\\ESENT\\Process\\vmtoolsd",
		"SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_SATA_CD01_______________1.00____",
		"SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_IDE_CDR10_______________1.00____",
		"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S&Rev_1.0",
		"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
		"SYSTEM\\CurrentControlSet\\Control\\CriticalDeviceDatabase\\root#vmwvmcihostdev",
		"SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers",
		"SYSTEM\\CurrentControlSet\\Services\\IRIS5",
		"SOFTWARE\\eEye Digital Security",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Wireshark",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\wireshark.exe",
		"SOFTWARE\\ZxSniffer.exe",
		"SOFTWARE\\Cygwin",
		"SOFTWARE\\B Labs\\Bopup Observer",
		"AppEvents\\Schemes\\Apps\\Bopup Observer",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Win Sniffer_is1",
		"SOFTWARE\\Win Sniffer",

		//vb
		"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
		"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
		"SYSTEM\\ControlSet001\\Services\\VBoxService",
		"SYSTEM\\ControlSet001\\Services\\VBoxSF",
		"SYSTEM\\ControlSet001\\Services\\VBoxVideo",
		"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
		"HARDWARE\\ACPI\\DSDT\\VBOX__",
		 "HARDWARE\\ACPI\\FADT\\VBOX__",
		"HARDWARE\\ACPI\\RSDT\\VBOX__" 
};

static char * spec_module_list[]={
	"CUCKOOMON.DLL",
	"dbghlp.dll",
	"sbiedll.dll",
};

static char * spec_kerner_file_lsit[]={
	"\\\\.\\pipe\\cuckoo",
	"\\\\.\\pipe\\VBoxTrayIPC",
	"\\\\.\\VBoxMiniRdrDN", "\\\\.\\pipe\\VBoxMiniRdDN", 
	"\\\\.\\VBoxTrayIPC", "\\\\.\\pipe\\VBoxTrayIPC" 

};

static char * spec_process_list[]={
	"Immunity",
	"ProcessHacker",
	"procexp",
	"procmon",
	"idaq",
	"regshot",
	"Wireshark",
	"sample.exe",
	"sub.exe"
};

static char * spec_service_list[]={

};

#endif