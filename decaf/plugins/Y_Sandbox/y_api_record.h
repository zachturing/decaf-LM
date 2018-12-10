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
#include "y_common.h"





//----------------kernel32:CopyFile----------------------------------
/*
BOOL WINAPI DeleteFile(
  _In_ LPCTSTR lpFileName
);
*/
static void Y_DeleteFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("kernel32.dll","DeleteFile",0);

	free(ctx);
}

static void Y_DeleteFile_Call(void *opaque)
{
	Y_print_api_info("kernel32.dll","DeleteFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);

	char lpFileName[1024];
	DECAF_read_mem(NULL,ctx->call_stack[3],sizeof(lpFileName),lpFileName);
	DECAF_printf("Y DeleteFile lpExistingFileName=%s\n",lpFileName);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_DeleteFile_Ret,ctx,sizeof(*ctx));
}

//----------------kernel32:CopyFile----------------------------------
/*
BOOL WINAPI CopyFile(
  _In_ LPCTSTR lpExistingFileName,
  _In_ LPCTSTR lpNewFileName,
  _In_ BOOL    bFailIfExists
);
*/
static void Y_CopyFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("kernel32.dll","CopyFile",0);

	free(ctx);
}

static void Y_CopyFile_Call(void *opaque)
{
	Y_print_api_info("kernel32.dll","CopyFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4*4, ctx->call_stack);

	char lpExistingFileName[1024];
	char lpNewFileName[1024];
	DECAF_read_mem(NULL,ctx->call_stack[2],sizeof(lpExistingFileName),lpExistingFileName);
	DECAF_read_mem(NULL,ctx->call_stack[3],sizeof(lpNewFileName),lpNewFileName);
	DECAF_printf("Y CopyFile lpExistingFileName=%s lpNewFileName=%s\n",lpExistingFileName,lpNewFileName);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_CopyFile_Ret,ctx,sizeof(*ctx));
}

//----------------kernel32:RegCreateKeyEx----------------------------------
/*
BOOL WINAPI CreateDirectoryEx(
  _In_     LPCTSTR               lpTemplateDirectory,
  _In_     LPCTSTR               lpNewDirectory,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
*/
static void Y_CreateDirectoryEx_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("kernel32.dll","CreateDirectoryEx",0);

	free(ctx);
}

static void Y_CreateDirectoryEx_Call(void *opaque)
{
	Y_print_api_info("kernel32.dll","CreateDirectoryEx",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4*4, ctx->call_stack);

	char lpTemplateDirectory[1024];
	char lpNewDirectory[1024];
	DECAF_read_mem(NULL,ctx->call_stack[2],sizeof(lpTemplateDirectory),lpTemplateDirectory);
	DECAF_read_mem(NULL,ctx->call_stack[3],sizeof(lpNewDirectory),lpNewDirectory);
	DECAF_printf("Y CreateDirectoryEx lpTemplateDirectory=%s lpNewDirectory=%s\n",lpTemplateDirectory,lpNewDirectory);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_CreateDirectoryEx_Ret,ctx,sizeof(*ctx));
}

//----------------kernel32:CreateDirectory----------------------------------
/*
BOOL WINAPI CreateDirectory(
  _In_     LPCTSTR               lpPathName,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
*/
static void Y_CreateDirectory_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("kernel32.dll","CreateDirectory",0);

	free(ctx);
}

static void Y_CreateDirectory_Call(void *opaque)
{
	Y_print_api_info("kernel32.dll","CreateDirectory",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, ctx->call_stack);

	char lpPathName[1024];
	DECAF_read_mem(NULL,ctx->call_stack[2],sizeof(lpPathName),lpPathName);
	DECAF_printf("Y CreateDirectory lpPathName=%s\n",lpPathName);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_CreateDirectory_Ret,ctx,sizeof(*ctx));
}


//----------------advapi32:RegCreateKeyEx----------------------------------
/*
LONG WINAPI RegCreateKeyEx(
  _In_       HKEY                  hKey,
  _In_       LPCTSTR               lpSubKey,
  _Reserved_ DWORD                 Reserved,
  _In_opt_   LPTSTR                lpClass,
  _In_       DWORD                 dwOptions,
  _In_       REGSAM                samDesired,
  _In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _Out_      PHKEY                 phkResult,
  _Out_opt_  LPDWORD               lpdwDisposition
);

*/
static void Y_RegCreateKeyEx_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("advapi32.dll","RegCreateKeyEx",0);

	free(ctx);
}

static void Y_RegCreateKeyEx_Call(void *opaque)
{
	Y_print_api_info("advapi32","RegCreateKeyEx",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 10*4, ctx->call_stack);

	char lpSubKey[1024];
	DECAF_read_mem(NULL,ctx->call_stack[3],sizeof(lpSubKey),lpSubKey);
	DECAF_printf("Y RegCreateKeyEx lpSubKey=%s\n",lpSubKey);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_RegCreateKeyEx_Ret,ctx,sizeof(*ctx));
}

//----------------advapi32:RegSetValueEx----------------------------------
/*
LONG WINAPI RegSetValueEx(
  _In_             HKEY    hKey,
  _In_opt_         LPCTSTR lpValueName,
  _Reserved_       DWORD   Reserved,
  _In_             DWORD   dwType,
  _In_       const BYTE    *lpData,
  _In_             DWORD   cbData
);
*/
static void Y_RegSetValueEx_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("advapi32.dll","RegSetValueEx",0);

	free(ctx);
}

static void Y_RegSetValueEx_Call(void *opaque)
{
	Y_print_api_info("advapi32","RegSetValueEx",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 7*4, ctx->call_stack);

	char lpSubKey[1024];
	DECAF_read_mem(NULL,ctx->call_stack[3],sizeof(lpSubKey),lpSubKey);
	DECAF_printf("Y RegSetValueEx lpSubKey=%s\n",lpSubKey);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_RegSetValueEx_Ret,ctx,sizeof(*ctx));
}


//----------------advapi32:RegDeleteKey----------------------------------
/*
LONG WINAPI RegDeleteValue(
  _In_     HKEY    hKey,
  _In_opt_ LPCTSTR lpValueName
);
*/
static void Y_RegDeleteValue_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("advapi32.dll","RegDeleteValue",0);

	free(ctx);
}

static void Y_RegDeleteValue_Call(void *opaque)
{
	Y_print_api_info("advapi32","RegDeleteValue",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, ctx->call_stack);

	char lpValueName[1024];
	DECAF_read_mem(NULL,ctx->call_stack[3],sizeof(lpValueName),lpValueName);
	DECAF_printf("Y RegDeleteValue lpValueName=%s\n",lpValueName);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_RegDeleteValue_Ret,ctx,sizeof(*ctx));
}

//----------------advapi32:RegDeleteKey----------------------------------
/*
LONG WINAPI RegDeleteKey(
  _In_ HKEY    hKey,
  _In_ LPCTSTR lpSubKey
);
*/
static void Y_RegDeleteKey_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("advapi32.dll","RegDeleteKey",0);

	free(ctx);
}

static void Y_RegDeleteKey_Call(void *opaque)
{
	Y_print_api_info("advapi32","RegDeleteKey",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, ctx->call_stack);

	char lpSubKey[1024];
	DECAF_read_mem(NULL,ctx->call_stack[3],sizeof(lpSubKey),lpSubKey);
	DECAF_printf("Y RegDeleteKey lpSubKey=%s\n",lpSubKey);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_RegDeleteKey_Ret,ctx,sizeof(*ctx));
}

//----------------advapi32:RegEnumKeyEx----------------------------------
/*
LONG WINAPI RegEnumKeyEx(
  _In_        HKEY      hKey,
  _In_        DWORD     dwIndex,
  _Out_       LPTSTR    lpName,
  _Inout_     LPDWORD   lpcName,
  _Reserved_  LPDWORD   lpReserved,
  _Inout_     LPTSTR    lpClass,
  _Inout_opt_ LPDWORD   lpcClass,
  _Out_opt_   PFILETIME lpftLastWriteTime
);

*/
static void Y_RegEnumKeyEx_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook

	char lpName[1024];
	DECAF_read_mem(NULL,ctx->call_stack[4],sizeof(lpName),lpName);
	DECAF_printf("Y RegEnumKeyEx lpName=%s\n",lpName);
	Y_print_api_info("advapi32.dll","RegEnumKeyEx",0);

	free(ctx);
}

static void Y_RegEnumKeyEx_Call(void *opaque)
{
	Y_print_api_info("advapi32","RegEnumKeyEx",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 9*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_RegEnumKeyEx_Ret,ctx,sizeof(*ctx));
}

//----------------Wininet:InternetReadFile----------------------------------
/*
BOOL InternetReadFile(
  _In_  HINTERNET hFile,
  _Out_ LPVOID    lpBuffer,
  _In_  DWORD     dwNumberOfBytesToRead,
  _Out_ LPDWORD   lpdwNumberOfBytesRead
)
*/
static void Y_InternetReadFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("Wininet.dll","InternetReadFile",0);
	free(ctx);
}

static void Y_InternetReadFile_Call(void *opaque)
{
	Y_print_api_info("Wininet","InternetReadFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 5*4, ctx->call_stack);

	uint32_t in_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &in_handle);
	DECAF_printf("Y InternetReadFile hFile=%x\n",in_handle);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_InternetReadFile_Ret,ctx,sizeof(*ctx));
}

//----------------Wininet:InternetWriteFile----------------------------------
/*
BOOL InternetWriteFile(
  _In_  HINTERNET hFile,
  _In_  LPCVOID   lpBuffer,
  _In_  DWORD     dwNumberOfBytesToWrite,
  _Out_ LPDWORD   lpdwNumberOfBytesWritten
);

*/
static void Y_InternetWriteFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("Wininet.dll","InternetWriteFile",0);
	free(ctx);
}

static void Y_InternetWriteFile_Call(void *opaque)
{
	Y_print_api_info("Wininet","InternetWriteFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 5*4, ctx->call_stack);

	uint32_t in_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &in_handle);
	DECAF_printf("Y InternetWriteFile hFile=%x\n",in_handle);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_InternetWriteFile_Ret,ctx,sizeof(*ctx));
}

//----------------Wininet:HttpOpenRequest----------------------------------
/*
HINTERNET HttpOpenRequest(
  _In_ HINTERNET hConnect,
  _In_ LPCTSTR   lpszVerb,
  _In_ LPCTSTR   lpszObjectName,
  _In_ LPCTSTR   lpszVersion,
  _In_ LPCTSTR   lpszReferer,
  _In_ LPCTSTR   *lplpszAcceptTypes,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);

*/
static void Y_HttpOpenRequest_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("Wininet.dll","HttpOpenRequest",0);
	free(ctx);
}

static void Y_HttpOpenRequest_Call(void *opaque)
{
	Y_print_api_info("Wininet","HttpOpenRequest",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 9*4, ctx->call_stack);

	uint32_t in_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &in_handle);
	DECAF_printf("Y HttpOpenRequest hConnect=%x\n",in_handle);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_HttpOpenRequest_Ret,ctx,sizeof(*ctx));
}


//----------------Wininet:InternetOpenUrl----------------------------------
/*
HINTERNET InternetOpenUrl(
  _In_ HINTERNET hInternet,
  _In_ LPCTSTR   lpszUrl,
  _In_ LPCTSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);
*/
static void Y_InternetOpenUrl_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("Wininet.dll","InternetOpenUrl",0);
	free(ctx);
}

static void Y_InternetOpenUrl_Call(void *opaque)
{
	Y_print_api_info("Wininet","InternetOpenUrl",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6*4, ctx->call_stack);

	char lpszUrl[1024];
	DECAF_read_mem(NULL, ctx->call_stack[2], sizeof(lpszUrl), lpszUrl);
	DECAF_printf("Y InternetOpenUrl lpszUrl=%s",lpszUrl);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_InternetOpenUrl_Ret,ctx,sizeof(*ctx));
}


//----------------Wininet:InternetOpen----------------------------------
/*
HINTERNET InternetOpen(
  _In_ LPCTSTR lpszAgent,
  _In_ DWORD   dwAccessType,
  _In_ LPCTSTR lpszProxyName,
  _In_ LPCTSTR lpszProxyBypass,
  _In_ DWORD   dwFlags
);

*/
static void Y_InternetOpen_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("Wininet.dll","InternetOpen",0);
	free(ctx);
}

static void Y_InternetOpen_Call(void *opaque)
{
	Y_print_api_info("Wininet","InternetOpen",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6*4, ctx->call_stack);

	char lpszAgent[1024];
	DECAF_read_mem(NULL, ctx->call_stack[1], sizeof(lpszAgent), lpszAgent);
	DECAF_printf("Y InternetOpen lpszAgent=%s",lpszAgent);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_InternetOpen_Ret,ctx,sizeof(*ctx));
}



//----------------ntdll:NtSetInformationFile----------------------------------
/*
NtSetInformationFile(
 IN HANDLE FileHandle,
 OUT PIO_STATUS_BLOCK IoStatusBlock,
 IN PVOID FileInformation,
 IN ULONG FileInformationLength,
 IN FILE_INFORMATION_CLASS FileInformationClass
 );
*/
static void Y_NtSetInformationFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook

	uint32_t out_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &out_handle);

	Y_print_api_info("Ntdll","NtSetInformationFile",0);
	DECAF_printf("out_handle=%08x\n", out_handle);
	free(ctx);
}

static void Y_NtSetInformationFile_Call(void *opaque)
{
	Y_print_api_info("Ntdll","NtSetInformationFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_NtSetInformationFile_Ret,ctx,sizeof(*ctx));
}



//----------------ntdll:NtQueryDirectoryFile----------------------------------
/*
NtQueryDirectoryFile(
 IN HANDLE FileHandle,
 IN HANDLE Event OPTIONAL,
 IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
 IN PVOID ApcContext OPTIONAL,
 OUT PIO_STATUS_BLOCK IoStatusBlock,
 OUT PVOID FileInformation,
 IN ULONG FileInformationLength,
 IN FILE_INFORMATION_CLASS FileInformationClass,
 IN BOOLEAN ReturnSingleEntry,
 IN PUNICODE_STRING FileName OPTIONAL,
 IN BOOLEAN RestartScan
 );
*/
static void Y_NtQueryDirectoryFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook

	uint32_t out_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &out_handle);

	Y_print_api_info("Ntdll","NtQueryDirectoryFile",0);
	DECAF_printf("in_handle=%08x\n", out_handle);
	free(ctx);
}

static void Y_NtDeviceIoControlFile_Call(void *opaque)
{
	Y_print_api_info("Ntdll","NtQueryDirectoryFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 12*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_NtQueryDirectoryFile_Ret,ctx,sizeof(*ctx));
}






//----------------ntdll:NtDeleteFile----------------------------------
/*
NtDeleteFile(
 IN POBJECT_ATTRIBUTES ObjectAttributes
 );
*/
static void Y_NtDeleteFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook

	uint32_t out_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &out_handle);

	Y_print_api_info("Ntdll","NtDeleteFile",0);
	DECAF_printf("in_handle=%08x\n", out_handle);
	free(ctx);
}

static void Y_NtDeleteFile_Call(void *opaque)
{
	Y_print_api_info("Ntdll","NtDeleteFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_CreateFile_Ret,ctx,sizeof(*ctx));
}


//----------------ntdll:NtWriteFile----------------------------------
/*NtWriteFile(
 IN HANDLE FileHandle,
 IN HANDLE Event OPTIONAL,
 IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
 IN PVOID ApcContext OPTIONAL,
 OUT PIO_STATUS_BLOCK IoStatusBlock,
 IN PVOID Buffer,
 IN ULONG Length,
 IN PLARGE_INTEGER ByteOffset OPTIONAL,
 IN PULONG Key OPTIONAL
 );*/

static void Y_NtWriteFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook

	uint32_t out_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &out_handle);

	Y_print_api_info("Ntdll","NtWriteFile",0);
	DECAF_printf("in_handle=%08x\n", out_handle);
	free(ctx);
}

static void Y_NtWriteFile_Call(void *opaque)
{
	Y_print_api_info("Ntdll","NtWriteFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_CreateFile_Ret,ctx,sizeof(*ctx));
}

//----------------ntdll:NtCreateFile----------------------------------
/*NTSTATUS NtCreateFile(
  _Out_    PHANDLE            FileHandle,
  _In_     ACCESS_MASK        DesiredAccess,
  _In_     POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_    PIO_STATUS_BLOCK   IoStatusBlock,
  _In_opt_ PLARGE_INTEGER     AllocationSize,
  _In_     ULONG              FileAttributes,
  _In_     ULONG              ShareAccess,
  _In_     ULONG              CreateDisposition,
  _In_     ULONG              CreateOptions,
  _In_     PVOID              EaBuffer,
  _In_     ULONG              EaLength
);
*/
static void Y_NtCreateFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook

	uint32_t out_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &out_handle);

	Y_print_api_info("Ntdll","NtCreateFile",0);
	DECAF_printf("out_handle=%08x\n", out_handle);
	free(ctx);
}

static void Y_NtCreateFile_Call(void *opaque)
{
	Y_print_api_info("Ntdll","NtCreateFilet",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 12*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_CreateFile_Ret,ctx,sizeof(*ctx));
}

//----------------ntdll:NTReadFile----------------------------------
/*NtReadFile(
       IN HANDLE FileHandle,
       IN HANDLE Event OPTIONAL,
       IN PIO_APC_ROUTINE UserApcRoutine OPTIONAL,
       IN PVOID UserApcContext OPTIONAL,
       OUT PIO_STATUS_BLOCK IoStatusBlock,
       OUT PVOID Buffer,
       IN ULONG BufferLength,
       IN PLARGE_INTEGER ByteOffset OPTIONAL,
       IN PULONG Key OPTIONAL     
       );
*/
static void Y_NtReadFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook

	Y_print_api_info("Ntdll","NtReadFile",0);
	free(ctx);
}

static void Y_NtReadFile_Call(void *opaque)
{
	Y_print_api_info("Ntdll","NtReadFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 10*4, ctx->call_stack);
	
	uint32_t in_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &in_handle);
	DECAF_printf("in_handle=%08x\n", in_handle);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_NtReadFile_Ret,ctx,sizeof(*ctx));
}


//----------------ntdll:NtOpenFile----------------------------------
/*NTSTATUS NtOpenFile(
  _Out_ PHANDLE            FileHandle,
  _In_  ACCESS_MASK        DesiredAccess,
  _In_  POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_ PIO_STATUS_BLOCK   IoStatusBlock,
  _In_  ULONG              ShareAccess,
  _In_  ULONG              OpenOptions
);
*/
static void Y_NtOpenFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook

	Y_print_api_info("Ntdll","NtOpenFile",0);
	free(ctx);
}

static void Y_NtOpenFile_Call(void *opaque)
{
	Y_print_api_info("Ntdll","NTReadFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 7*4, ctx->call_stack);
	
	uint32_t in_handle;
	DECAF_read_mem(NULL, ctx->call_stack[1], 4, &in_handle);
	DECAF_printf("in_handle=%08x\n", in_handle);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_NtOpenFile_Ret,ctx,sizeof(*ctx));
}



//------------------Hook function----------------------------
static void Y_api_record(uint32_t targetcr3){
//ntdll
 hookapi_hook_function_byname("ntdll.dll","NtCreateFile",1,targetcr3,Y_GetSystemInfo_Call,NULL,0);
 hookapi_hook_function_byname("ntdll.dll","NtReadFile",1,targetcr3,Y_NtReadFile_Call,NULL,0);
 hookapi_hook_function_byname("ntdll.dll","NtOpenFile",1,targetcr3,Y_NtOpenFile_Call,NULL,0);
 hookapi_hook_function_byname("ntdll.dll","NtWriteFile",1,targetcr3,Y_NtWriteFile_Call,NULL,0);
 hookapi_hook_function_byname("ntdll.dll","NtDeleteFile",1,targetcr3,Y_NtDeleteFile_Call,NULL,0);
 hookapi_hook_function_byname("ntdll.dll","NtDeviceIoControlFile",1,targetcr3,Y_NtDeviceIoControlFile_Call,NULL,0);
 hookapi_hook_function_byname("ntdll.dll","NtSetInformationFile",1,targetcr3,Y_NtSetInformationFile_Call,NULL,0);
//kerner 32
 hookapi_hook_function_byname("kernel32.dll","CreateDirectoryW",1,targetcr3,Y_CreateDirectory_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","CreateDirectoryA",1,targetcr3,Y_CreateDirectory_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","CreateDirectoryExW",1,targetcr3,Y_CreateDirectoryEx_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","CreateDirectoryExA",1,targetcr3,Y_CreateDirectoryEx_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","CopyFileW",1,targetcr3,Y_CopyFile_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","CopyFileA",1,targetcr3,Y_CopyFile_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","CopyFileExW",1,targetcr3,Y_CopyFile_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","CopyFileExA",1,targetcr3,Y_CopyFile_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","DeleteFileA",1,targetcr3,Y_DeleteFile_Call,NULL,0);
 hookapi_hook_function_byname("kernel32.dll","DeleteFile",1,targetcr3,Y_DeleteFile_Call,NULL,0);
//advapi32
 hookapi_hook_function_byname("advapi32.dll","RegEnumKeyEx",1,targetcr3,Y_RegEnumKeyEx_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegEnumKeyExA",1,targetcr3,Y_RegEnumKeyEx_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegDeleteKey",1,targetcr3,Y_RegDeleteKey_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegDeleteKeyA",1,targetcr3,Y_RegDeleteKey_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegDeleteKeyExA",1,targetcr3,Y_RegDeleteKey_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegSetValueEx",1,targetcr3,Y_RegSetValueEx_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegSetValueExA",1,targetcr3,Y_RegSetValueEx_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegDeleteValue",1,targetcr3,Y_RegDeleteValue_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegDeleteValueA",1,targetcr3,Y_RegDeleteValue_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegCreateKeyEx",1,targetcr3,Y_RegCreateKeyEx_Call,NULL,0);
 hookapi_hook_function_byname("advapi32.dll","RegCreateKeyExA",1,targetcr3,Y_RegCreateKeyEx_Call,NULL,0);

//Wininet
 hookapi_hook_function_byname("Wininet.dll","InternetOpenA",1,targetcr3,Y_InternetOpen_Call,NULL,0);
 hookapi_hook_function_byname("Wininet.dll","InternetOpenW",1,targetcr3,Y_InternetOpen_Call,NULL,0);
 hookapi_hook_function_byname("Wininet.dll","InternetOpenUrlA",1,targetcr3,Y_InternetOpenUrl_Call,NULL,0);
 hookapi_hook_function_byname("Wininet.dll","InternetOpenUrlW",1,targetcr3,Y_InternetOpenUrl_Call,NULL,0);
 hookapi_hook_function_byname("Wininet.dll","HttpOpenRequestA",1,targetcr3,Y_HttpOpenRequest_Call,NULL,0);
 hookapi_hook_function_byname("Wininet.dll","HttpOpenRequestW",1,targetcr3,Y_HttpOpenRequest_Call,NULL,0);
 hookapi_hook_function_byname("Wininet.dll","InternetWriteFile",1,targetcr3,Y_InternetWriteFile_Call,NULL,0);		
 hookapi_hook_function_byname("Wininet.dll","InternetReadFile",1,targetcr3,Y_InternetReadFile_Call,NULL,0);		

}