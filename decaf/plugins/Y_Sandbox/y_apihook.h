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



static void Y_GetSystemInfo_Call(void *);
static void Y_GetDiskFreeSpaceEx_Call(void *);
static void Y_RegOpenKeyEx_Call(void*);
static void Y_GetFileAttributes_Call(void*);
static void Y_CreateFile_Call(void*);
static void Y_GetComputerName_Call(void*);
static void Y_GetUserName_Call(void*);
static void Y_FindWindow_Call(void*);
static void Y_FindFirstFile_Call(void*);
static void Y_DnsQuery_Call(void*);
static void Y_InternetConnect_Call(void*);
static void Y_gethostbyname_Call(void *opaque);
static void Y_URLDownloadToFile_Call(void *param);
static void Y_InternetCheckConnection_Call(void *opaque);
static void Y_GetModuleHandle_Call(void *opaque);
static void Y_RegQueryValueEx_Call(void *opaque);
static void Y_Process32First_Call(void *opaque);
static void Y_FindFirstFileEx_Call(void *opaque);
static void Y_RegQueryValue_Call(void *opaque);

//------------------Hook function----------------------------
void Y_api_hook(uint32_t targetcr3){
	 hookapi_hook_function_byname("Kernel32.dll","GetSystemInfo",1,targetcr3,Y_GetSystemInfo_Call,NULL,0);    
     hookapi_hook_function_byname("Kernel32.dll","GetDiskFreeSpaceExA",1,targetcr3,Y_GetDiskFreeSpaceEx_Call,NULL,0);
     hookapi_hook_function_byname("Kernel32.dll","GetDiskFreeSpaceExW",1,targetcr3,Y_GetDiskFreeSpaceEx_Call,NULL,0);
	 hookapi_hook_function_byname("Advapi32.dll","RegOpenKeyExA",1,targetcr3,Y_RegOpenKeyEx_Call,NULL,0);
	 hookapi_hook_function_byname("Advapi32.dll","RegOpenKeyExW",1,targetcr3,Y_RegOpenKeyEx_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","GetFileAttributes",1,targetcr3,Y_GetFileAttributes_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","GetFileAttributesA",1,targetcr3,Y_GetFileAttributes_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","CreateFile",1,targetcr3,Y_CreateFile_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","CreateFileA",1,targetcr3,Y_CreateFile_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","GetComputerName",1,targetcr3,Y_GetComputerName_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","GetComputerNameA",1,targetcr3,Y_GetComputerName_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","GetUserName",1,targetcr3,Y_GetUserName_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","GetUserNameA",1,targetcr3,Y_GetUserName_Call,NULL,0);
	 hookapi_hook_function_byname("User32.dll","FindWindow",1,targetcr3,Y_FindWindow_Call,NULL,0);
	 hookapi_hook_function_byname("User32.dll","FindWindowA",1,targetcr3,Y_FindWindow_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","FindFirstFile",1,targetcr3,Y_GetUserName_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","FindFirstFileA",1,targetcr3,Y_GetUserName_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","FindFirstFileEx",1,targetcr3,Y_GetUserName_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","FindFirstFileExA",1,targetcr3,Y_GetUserName_Call,NULL,0);
	 hookapi_hook_function_byname("Dnsapi.dll","DnsQuery",1,targetcr3,Y_DnsQuery_Call,NULL,0);
	 hookapi_hook_function_byname("Dnsapi.dll","DnsQuery_A",1,targetcr3,Y_DnsQuery_Call,NULL,0);
	 hookapi_hook_function_byname("Dnsapi.dll","DnsQuery_W",1,targetcr3,Y_DnsQuery_Call,NULL,0);
	 hookapi_hook_function_byname("Wininet.dll","InternetConnect",1,targetcr3,Y_InternetConnect_Call,NULL,0);
	 hookapi_hook_function_byname("Wininet.dll","InternetConnectA",1,targetcr3,Y_InternetConnect_Call,NULL,0);
	 hookapi_hook_function_byname("Wininet.dll","InternetCheckConnection",1,targetcr3,Y_InternetConnect_Call,NULL,0);
	 hookapi_hook_function_byname("Wininet.dll","InternetCheckConnectionA",1,targetcr3,Y_InternetConnect_Call,NULL,0);
	 hookapi_hook_function_byname("Ws2_32.dll","gethostbyname",1,targetcr3,Y_gethostbyname_Call,NULL,0);
	 hookapi_hook_function_byname("urlmon.dll","URLDownloadToFile",1,targetcr3,Y_URLDownloadToFile_Call,NULL,0);
	 hookapi_hook_function_byname("urlmon.dll","URLDownloadToFileA",1,targetcr3,Y_URLDownloadToFile_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","GetModuleHandle",1,targetcr3,Y_GetModuleHandle_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","GetModuleHandleA",1,targetcr3,Y_GetModuleHandle_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","Process32First",1,targetcr3,Y_Process32First_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","Process32FirstW",1,targetcr3,Y_Process32First_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","Process32Next",1,targetcr3,Y_Process32First_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","Process32NextW",1,targetcr3,Y_Process32First_Call,NULL,0);
	 hookapi_hook_function_byname("Advapi32.dll","RegQueryValueExA",1,targetcr3,Y_RegQueryValueEx_Call,NULL,0);
	 hookapi_hook_function_byname("Advapi32.dll","RegQueryValueExW",1,targetcr3,Y_RegQueryValueEx_Call,NULL,0);
	 hookapi_hook_function_byname("Advapi32.dll","RegQueryValueA",1,targetcr3,Y_RegQueryValue_Call,NULL,0);
	 hookapi_hook_function_byname("Advapi32.dll","RegQueryValueW",1,targetcr3,Y_RegQueryValue_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","FindFirstFileEx",1,targetcr3,Y_FindFirstFileEx_Call,NULL,0);
	 hookapi_hook_function_byname("Kernel32.dll","FindFirstFileExA",1,targetcr3,Y_FindFirstFileEx_Call,NULL,0);


}

//---------------------------------Advapi32::RegQueryValue-------------------------------------
/*
LONG WINAPI RegQueryValue(
  _In_        HKEY    hKey,
  _In_opt_    LPCTSTR lpSubKey,
  _Out_opt_   LPTSTR  lpValue,
  _Inout_opt_ PLONG   lpcbValue
);
*/
static void Y_RegQueryValue_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char lpValueName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[2], sizeof(lpValueName), &lpValueName);
	Y_print_api_info("Advapi32.dll","RegQueryValue",0);
	DECAF_printf("Y RegQueryValue lpValueName=%s\n",lpValueName);

	free(ctx);
}

static void Y_RegQueryValue_Call(void *opaque)
{
	Y_print_api_info("Advapi32.dll","RegQueryValue",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 5*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_RegQueryValue_Ret,ctx,sizeof(*ctx));
}

//----------------kernel32:FindFirstFileEx----------------------------------
/*
HANDLE WINAPI FindFirstFileEx(
  _In_       LPCTSTR            lpFileName,
  _In_       FINDEX_INFO_LEVELS fInfoLevelId,
  _Out_      LPVOID             lpFindFileData,
  _In_       FINDEX_SEARCH_OPS  fSearchOp,
  _Reserved_ LPVOID             lpSearchFilter,
  _In_       DWORD              dwAdditionalFlags
);
*/
static void Y_FindFirstFileEx_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);  //remove hook
	Y_print_api_info("Kerner32.dll","FindFirstFileEx",0);
	free(ctx);
}

static void Y_FindFirstFileEx_Call(void *opaque)
{
	Y_print_api_info("Kerner32","FindFirstFileEx",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4*4, ctx->call_stack);

	char lpFileName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[1], sizeof(lpFileName), lpFileName);
	DECAF_printf("Y lpFileName=%s\n",lpFileName);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_FindFirstFileEx_Ret,ctx,sizeof(*ctx));
}

//---------------------------------Advapi32::RegQueryValueEx-------------------------------------
/*
LONG WINAPI RegQueryValueEx(
  _In_        HKEY    hKey,
  _In_opt_    LPCTSTR lpValueName,
  _Reserved_  LPDWORD lpReserved,
  _Out_opt_   LPDWORD lpType,
  _Out_opt_   LPBYTE  lpData,
  _Inout_opt_ LPDWORD lpcbData
);
*/
static void Y_RegQueryValueEx_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char lpValueName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[2], sizeof(lpValueName), &lpValueName);
	Y_print_api_info("Advapi32.dll","RegQueryValueEx",0);
	DECAF_printf("Y RegQueryValueEx lpValueName=%s\n",lpValueName);

	
	free(ctx);
}

static void Y_RegQueryValueEx_Call(void *opaque)
{
	Y_print_api_info("Advapi32.dll","RegQueryValueEx",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 7*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_RegQueryValueEx_Ret,ctx,sizeof(*ctx));
}


//---------------------------------kernel32::Process32First-------------------------------------
/*
BOOL WINAPI Process32First(
    HANDLE hSnapshot,//_in
    LPPROCESSENTRY32 lppe//_out
);

typedef struct tagPROCESSENTRY32 {
    DWORD dwSize; // 结构大小；
    DWORD cntUsage; // 此进程的引用计数；
    DWORD th32ProcessID; // 进程ID;
    DWORD th32DefaultHeapID; // 进程默认堆ID；
    DWORD th32ModuleID; // 进程模块ID；
    DWORD cntThreads; // 此进程开启的线程计数；
    DWORD th32ParentProcessID;// 父进程ID；
    LONG pcPriClassBase; // 线程优先权；
    DWORD dwFlags; // 保留；
    WCHAR szExeFile[MAX_PATH]; // 进程全名；
} PROCESSENTRY32;
*/
static void Y_Process32First_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char szExeFile[1024];
	DECAF_read_mem(NULL, ctx->call_stack[2]+36, sizeof(szExeFile), &szExeFile);
	Y_print_api_info("kernel32.dll","Process32First",0);
	DECAF_printf("Y Process32First szExeFile=%s\n",szExeFile);

	
	free(ctx);
}

static void Y_Process32First_Call(void *opaque)
{
	Y_print_api_info("kernel32.dll","Process32First",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_Process32First_Ret,ctx,sizeof(*ctx));
}

//---------------------------------kernel32::GetModuleHandle-------------------------------------
/*
HMODULE WINAPI GetModuleHandle(
  _In_opt_ LPCTSTR lpModuleName
);
*/
static void Y_GetModuleHandle_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char lpModuleName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[2], sizeof(lpModuleName), &lpModuleName);
	Y_print_api_info("kernel32.dll","GetModuleHandle",0);
	DECAF_printf("Y GetModuleHandle lpModuleName=%s\n",lpModuleName);
	cpu_single_env->regs[R_EAX]=0; //NULL
	
	free(ctx);
}

static void Y_GetModuleHandle_Call(void *opaque)
{
	Y_print_api_info("kernel32.dll","GetModuleHandle",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_GetModuleHandle_Ret,ctx,sizeof(*ctx));
}


//---------------------------------Wininet.dll-------------------------------------
/*
BOOL InternetCheckConnection(
  _In_ LPCTSTR lpszUrl,
  _In_ DWORD   dwFlags,
  _In_ DWORD   dwReserved
);
*/
static void Y_InternetCheckConnection_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char url[1024];
	DECAF_read_mem(NULL, ctx->call_stack[2], sizeof(url), &url);
	Y_print_api_info("Wininet.dll","InternetCheckConnection",0);
	DECAF_printf("Y InternetCheckConnection szURL=%s\n",url);
	cpu_single_env->regs[R_EAX]=1; //internet ok
	
	free(ctx);
}

static void Y_InternetCheckConnection_Call(void *opaque)
{
	Y_print_api_info("Wininet.dll","InternetCheckConnection",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_InternetCheckConnection_Ret,ctx,sizeof(*ctx));
}

//------------------------------urlmon, URLDownloadToFileW------------------------------------------
/*
HRESULT URLDownloadToFile(
             LPUNKNOWN            pCaller,
             LPCTSTR              szURL,
             LPCTSTR              szFileName,
  _Reserved_ DWORD                dwReserved,
             LPBINDSTATUSCALLBACK lpfnCB
);
*/
static void Y_URLDownloadToFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char url[1024];
	DECAF_read_mem(NULL, ctx->call_stack[2], sizeof(url), &url);
	Y_print_api_info("Ws2_32.dll","URLDownloadToFile",0);
	DECAF_printf("Y URLDownloadToFile szURL=%s\n",url);
	cpu_single_env->regs[R_EAX]=1; //internet ok
	
	free(ctx);
}

static void Y_URLDownloadToFile_Call(void *opaque)
{
	Y_print_api_info("Ws2_32.dll","URLDownloadToFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_URLDownloadToFile_Ret,ctx,sizeof(*ctx));
}

//------------------------------Ws2_32.dll:gethostbyname------------------------------------------
/*
struct hostent* FAR gethostbyname(
  _In_ const char *name
);
*/
static void Y_gethostbyname_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char name[1024];
	DECAF_read_mem(NULL, ctx->call_stack[1], sizeof(name), &name);
	Y_print_api_info("Ws2_32.dll","gethostbyname",0);
	DECAF_printf("Y gethostbyname name=%s\n",name);
	
	free(ctx);
}

static void Y_gethostbyname_Call(void *opaque)
{
	Y_print_api_info("Ws2_32.dll","gethostbyname",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_gethostbyname_Ret,ctx,sizeof(*ctx));
}

//-----------------Wininet.dll:InternetConnect-----------------------------------------
/*
HINTERNET InternetConnect(
  _In_ HINTERNET     hInternet,
  _In_ LPCTSTR       lpszServerName,
  _In_ INTERNET_PORT nServerPort,
  _In_ LPCTSTR       lpszUsername,
  _In_ LPCTSTR       lpszPassword,
  _In_ DWORD         dwService,
  _In_ DWORD         dwFlags,
  _In_ DWORD_PTR     dwContext
);
*/
static void Y_InternetConnect_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char lpszServerName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[2], sizeof(lpszServerName), &lpszServerName);
	Y_print_api_info("Wininet.dll","InternetConnect",0);
	DECAF_printf("Y InternetConnect lpszServerName=%s\n",lpszServerName);
	cpu_single_env->regs[R_EAX]=1;

	free(ctx);
}

static void Y_InternetConnect_Call(void *opaque)
{
	Y_print_api_info("Wininet.dll","InternetConnect",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 9*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_InternetConnect_Ret,ctx,sizeof(*ctx));
}


//-----------------dnsapi::DnsQuery-----------------------------------------
/*
DNS_STATUS WINAPI DnsQuery(
  _In_        PCTSTR      lpstrName,
  _In_        WORD        wType,
  _In_        DWORD       Options,
  _Inout_opt_ PVOID       pExtra,
  _Out_opt_   PDNS_RECORD *ppQueryResultsSet,
  _Out_opt_   PVOID       *pReserved
);
*/

static void Y_DnsQuery_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char lpstrName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[1], sizeof(lpstrName), &lpstrName);
	Y_print_api_info("dnsapi.dll","DnsQuery",0);
	DECAF_printf("Y DnsQuery lpstrName=%s\n",lpstrName);

	
	free(ctx);
}

static void Y_DnsQuery_Call(void *opaque)
{
	Y_print_api_info("dnsapi.dll","DnsQuery",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 7*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_DnsQuery_Ret,ctx,sizeof(*ctx));
}

//-------------------------Kerner32::FindFirstFile---------------------------
/*HANDLE WINAPI FindFirstFile(
  _In_  LPCTSTR           lpFileName,
  _Out_ LPWIN32_FIND_DATA lpFindFileData
);*/
static void Y_FindFirstFile_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;
	hookapi_remove_hook(ctx->hook_handle);
    
    char lpFileName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[1], sizeof(lpFileName), &lpFileName);
	Y_print_api_info("Kernel32.dll","FindFirstFile",0);
	DECAF_printf("Y FindFirstFile lpFileName=%s\n",lpFileName);

	int i=0;
	for(;i<sizeof(spec_file_list)/sizeof(char*);i++)
		if(strcasecmp(spec_file_list[i],lpFileName)==0){
			cpu_single_env->regs[R_EAX]=0;
			DECAF_printf("Y FindWindow changeName special_name[i] not exist\n ",spec_file_list[i],"Y");
			break;
		}
	
	free(ctx);
}

static void Y_FindFirstFile_Call(void *opaque)
{
	Y_print_api_info("User32.dll","FindFirstFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_FindFirstFile_Ret,ctx,sizeof(*ctx));
}



//------------------User32::FindWindow----------------------------------------
/*HWND WINAPI FindWindow(
  _In_opt_ LPCTSTR lpClassName,
  _In_opt_ LPCTSTR lpWindowName
);
*/
static void Y_FindWindow_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;

	hookapi_remove_hook(ctx->hook_handle);
    
    char lpClassName[1024];
    char lpWindowName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[1], sizeof(lpClassName), &lpClassName);
	DECAF_read_mem(NULL, ctx->call_stack[2], sizeof(lpWindowName), &lpWindowName);
	Y_print_api_info("User32.dll","FindWindow",0);
	DECAF_printf("Y GetUserName lpClassName=%s  lpWindowName=%s\n",lpClassName,lpWindowName);

	char *special_name[]={"VBoxTrayToolWndClass","VBoxTrayToolWnd"};

	int i=0;
	for(;i<sizeof(special_name)/sizeof(char*);i++)
		if(strcasecmp(special_name[i],lpClassName)==0 || strcasecmp(special_name[i],lpWindowName)==0){
			cpu_single_env->regs[R_EAX]=0;
			DECAF_printf("Y FindWindow changeName %s not exist\n ",special_name[i]);
			break;
		}
	
	free(ctx);
}

static void Y_FindWindow_Call(void *opaque)
{
	Y_print_api_info("User32.dll","FindWindow",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_FindWindow_Ret,ctx,sizeof(*ctx));
}

//----------------kernel32::GetUserName----------------------------------
/*
BOOLWINAPI GetUserName(
    __out         LPTSTRlpBuffer,
    __in_out      LPDWORDlpnSize
);
*/
static void Y_GetUserName_Ret(void *param)
{
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;

	hookapi_remove_hook(ctx->hook_handle);
    
    
    char name[1024];

	DECAF_read_mem(NULL, ctx->call_stack[1], sizeof(name), &name);

	Y_print_api_info("kernel32.dll","GetUserName",0);
	DECAF_printf("Y GetUserName UserName %s\n",name);

	char *special_name[]={"USER", "ANDY", "COMPUTERNAME", "CUCKOO", "SANDBOX", "NMSDBOX",
		"XXXX-OX", "CWSX", "WILBERT-SC", "XPAMAST-SC"};

	int i=0;
	for(;i<sizeof(special_name)/sizeof(char*);i++)
		if(strcasecmp(special_name[i],name)==0){
			DECAF_write_mem(NULL, ctx->call_stack[1],1,"Y");
			DECAF_printf("Y GetUserName Change GetUserName %s to %s\n ",special_name[i],"Y");
			break;
		}
	
	free(ctx);
}

static void Y_GetUserName_Call(void *opaque)
{
	Y_print_api_info("Kernel32.dll","GetUserName",1); 
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_GetUserName_Ret,ctx,sizeof(*ctx));
}


//----------------kernel32::GetComputerName----------------------------------
/*
BOOLWINAPI GetComputerName(
    __out         LPTSTRlpBuffer,
    __in_out      LPDWORDlpnSize
);
*/
static void Y_GetComputerName_Ret(void *param)
{
	Y_print_api_info("kernel32.dll","GetComputerName",0); 
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;

	hookapi_remove_hook(ctx->hook_handle);
   
    char name[1024];

	DECAF_read_mem(NULL, ctx->call_stack[1], sizeof(name), &name);
	DECAF_printf("Y GetComputerName COMPUTERNAME %s\n",name);

	char *special_name[]={"USER", "ANDY", "COMPUTERNAME", "CUCKOO", "SANDBOX", "NMSDBOX",
		"XXXX-OX", "CWSX", "WILBERT-SC", "XPAMAST-SC"};

	int i=0;
	for(;i<sizeof(special_name)/sizeof(char*);i++)
		if(strcasecmp(special_name[i],name)==0){
			DECAF_write_mem(NULL, ctx->call_stack[1],1, &"Y");
			DECAF_printf("Y GetComputerName Change COMPUTERNAME %s to %s\n ",special_name[i],"Y");
			break;
		}
	
	free(ctx);
}

static void Y_GetComputerName_Call(void *opaque)
{
	Y_print_api_info("Kernel32.dll","GetComputerName",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_GetComputerName_Ret,ctx,sizeof(*ctx));
}

//----------------kernel32::GetSystemInfo----------------------------------
/*
void WINAPI GetSystemInfo(_Out_ LPSYSTEM_INFO lpSystemInfo)
*/
static void Y_GetSystemInfo_Ret(void *param)
{
	Y_print_api_info("Kernel32.dll","GetSystemInfo",0);
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;

	hookapi_remove_hook(ctx->hook_handle);
    int value;

	DECAF_read_mem(NULL, ctx->call_stack[1]+20, 4, &value);
	if(value==1 || value==2){
		DECAF_printf("Y GetSystemInfo core=%d\n",value);
    	value=16;
		DECAF_write_mem(NULL, ctx->call_stack[1]+20, 4, &value);
	}
	DECAF_printf("Y GetSystemInfo Change Core=%d\n ",value);
	free(ctx);
}

static void Y_GetSystemInfo_Call(void *opaque)
{
	Y_print_api_info("Kernel32.dll","GetSystemInfo",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                         Y_GetSystemInfo_Ret,ctx,sizeof(*ctx));
}

//------------------kernel32::GetDiskFreeSpaceEx-------------------------
/**
BOOL WINAPI GetDiskFreeSpaceExA(
    __in_opt LPCSTR lpDirectoryName,
    __out_opt PULARGE_INTEGER lpFreeBytesAvailableToCaller,
    __out_opt PULARGE_INTEGER lpTotalNumberOfBytes,
    __out_opt PULARGE_INTEGER lpTotalNumberOfFreeBytes
    );
*/
static void Y_GetDiskFreeSpaceEx_Ret(void *param)
{
	Y_print_api_info("kernel32.dll","GetDiskFreeSpaceEx",0);
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;

	hookapi_remove_hook(ctx->hook_handle);  //remove hook


    int value[2];
   	const int GB=1024*1024*1024;
	DECAF_read_mem(NULL, ctx->call_stack[3],8, &value);

	if(value[1]*4+value[0]/GB<100){
		DECAF_printf("Y GetDiskFreeSpace TotalSpace=%dGB\n",value[1]*4+value[0]/GB);
    	value[1]=100;
    	DECAF_write_mem(NULL,ctx->call_stack[3],8,&value);
		DECAF_printf("Y GetDsikFreeSpace Change TotalSpace=%dGB\n",value[1]*4+value[0]/GB);
	}

	free(ctx); 
}

static void Y_GetDiskFreeSpaceEx_Call(void *opaque)
{
	Y_print_api_info("Kernel32.dll","GetDsikFreeSpaceEx",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 5*4, ctx->call_stack);
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                        Y_GetDiskFreeSpaceEx_Ret,ctx,sizeof(*ctx));
}


//------------------Advapi32.dll::RegOpenKeyEx------------------------------
/*
LONG WINAPI RegOpenKeyEx(
  _In_     HKEY    hKey,
  _In_opt_ LPCTSTR lpSubKey,
  _In_     DWORD   ulOptions,
  _In_     REGSAM  samDesired,
  _Out_    PHKEY   phkResult
);
*/
static void Y_RegOpenKeyEx_Ret(void *param)
{
	Y_print_api_info("Advapi32.dll","RegOpenKeyEx",0);
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;

	hookapi_remove_hook(ctx->hook_handle);  //remove hook
    
    //ret value eax

	free(ctx); 
}

static void Y_RegOpenKeyEx_Call(void *opaque)
{
	Y_print_api_info("Advapi32.dll","RegOpenKeyEx",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6*4, ctx->call_stack);
	
	char reg_key[1024];
	DECAF_read_mem(NULL, ctx->call_stack[3],sizeof(reg_key), &reg_key);
	DECAF_printf("Y RegOpenKeyEx reg_key=%s\n",reg_key);

	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                        Y_RegOpenKeyEx_Ret,ctx,sizeof(*ctx));
}

//---------------------------Kernel32::GetFileAttributes------------------------------------------------------------
/*
DWORD WINAPI GetFileAttributes(_In_ LPCTSTR lpFileName); return 
*/
static void Y_GetFileAttributes_Ret(void *param)
{
	Y_print_api_info("Kernel32.dll","GetFileAttributes",0);
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;

	hookapi_remove_hook(ctx->hook_handle);  //remove hook
    
    //ret value eax

	free(ctx); 
}

static void Y_GetFileAttributes_Call(void *opaque)
{
	Y_print_api_info("Kernel32.dll","GetFileAttributes",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2*4, ctx->call_stack);
	
	char lpFileName[1024];
	DECAF_read_mem(NULL, ctx->call_stack[1],sizeof(lpFileName), &lpFileName);
	DECAF_printf("Y GetFileAttributes lpFileName=%s\n",lpFileName);

	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                        Y_GetFileAttributes_Ret,ctx,sizeof(*ctx));
}

//---------------------------Kernel32::-----------------------------------------------------------
/*HANDLE WINAPI CreateFile(
  _In_     LPCTSTR               lpFileName,
  _In_     DWORD                 dwDesiredAccess,
  _In_     DWORD                 dwShareMode,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_     DWORD                 dwCreationDisposition,
  _In_     DWORD                 dwFlagsAndAttributes,
  _In_opt_ HANDLE                hTemplateFile
);
*/
static void Y_CreateFile_Ret(void *param)
{
	Y_print_api_info("Kernel32.dll","CreateFile",0);
	Y_Func_Stack *ctx = (Y_Func_Stack*)param;

	hookapi_remove_hook(ctx->hook_handle);  //remove hook
    
    //ret value eax

	free(ctx); 
}

static void Y_CreateFile_Call(void *opaque)
{
	Y_print_api_info("Kernel32.dll","CreateFile",1);
	Y_Func_Stack *ctx = (Y_Func_Stack*)
			malloc(sizeof(Y_Func_Stack));
	if(!ctx) //run out of memory
		return;

	DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 8*4, ctx->call_stack);
	
	char lpFileName[1024];;
	DECAF_read_mem(NULL, ctx->call_stack[1],sizeof(lpFileName), &lpFileName);
	DECAF_printf("Y CreateFile lpFileName=%s\n",lpFileName);

	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0],
                        Y_CreateFile_Ret,ctx,sizeof(*ctx));
}



