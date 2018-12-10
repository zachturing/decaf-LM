#ifndef _APIHOOK_FILE_HANDLE_H_
#define _APIHOOK_FILE_HANDLE_H_

#include <string>
#include <iostream>
using namespace std;

void Win_OpenFile_Ret(void* );
void Win_OpenFile_Call(void* );

void Win_CreateFileW_Ret(void* );
void Win_CreateFileW_Call(void* );

void Win_CreateFileA_Ret(void* );
void Win_CreateFileA_Call(void* );

void Win_ReadFile_Ret(void* );
void Win_ReadFile_Call(void* );

void Win_WriteFile_Ret(void* );
void Win_WriteFile_Call(void* );


void Win_DeleteFileA_Ret(void* );
void Win_DeleteFileA_Call(void* );
	
void Win_DeleteFileW_Ret(void* );
void Win_DeleteFileW_Call(void* );


void Win_sendto_Ret(void* );
void Win_sendto_Call(void* );


void Win_send_Ret(void* );
void Win_send_Call(void* );


void Win_MoveFileAll_Ret(void* );

void Win_MoveFileA_Call(void* );
void Win_MoveFileW_Call(void* );

void Win_MoveFileExA_Call(void* );
void Win_MoveFileExW_Call(void* );

void Win_MoveFileWithProgressA_Call(void* );
void Win_MoveFileWithProgressW_Call(void* );

void Win_MoveFileTransactedA_Call(void* );
void Win_MoveFileTransactedW_Call(void* );

struct CBaseHook
{
public:
	CBaseHook(string funcname):_funcname(funcname), _handle(DECAF_NULL_HANDLE)
	{

	}
public:
	DECAF_Handle _handle;
	string _funcname;
};

struct CMoveFile : public CBaseHook
{
public:
	CMoveFile(string funcname):CBaseHook(funcname)
	{
		//cout<<_funcname<<endl;
		DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 3 * 4, _stack);
		_handle = hookapi_hook_return(_stack[0], Win_MoveFileAll_Ret, this, sizeof(CMoveFile));
	}
public:
	uint32_t _stack[3];   			//只需要返回参数和前两个参数
};

struct COpenFile : public CBaseHook
{
public:
	COpenFile(string funcname):CBaseHook(funcname)
	{
		//cout<<_funcname<<endl;
		DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 4 * 4, _stack);
		_handle = hookapi_hook_return(_stack[0], Win_OpenFile_Ret, this, sizeof(COpenFile));
	}

public:
	uint32_t _stack[4];
};

struct CCreateFile : public CBaseHook
{
public:
	CCreateFile(string funcname):CBaseHook(funcname)
	{
		//cout<<_funcname<<endl;
		DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 8 * 4, _stack);
		if(_funcname == string("CreateFileW"))
		{
			_handle = hookapi_hook_return(_stack[0], Win_CreateFileW_Ret, this, sizeof(CCreateFile));
		}
		if(_funcname == string("CreateFileA"))
		{
			_handle = hookapi_hook_return(_stack[0], Win_CreateFileA_Ret, this, sizeof(CCreateFile));
		}
	}

public:
	uint32_t _stack[8];
};

struct CReadFile : public CBaseHook
{
public:
	CReadFile(string funcname):CBaseHook(funcname)
	{
		//cout<<_funcname<<endl;
		DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6 * 4, _stack);
		_handle = hookapi_hook_return(_stack[0], Win_ReadFile_Ret, this, sizeof(CReadFile));
	}

public:
	uint32_t _stack[6];
};

struct CWriteFile : public CBaseHook
{
public:
	CWriteFile(string funcname):CBaseHook(funcname)
	{
		//cout<<_funcname<<endl;
		DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 6 * 4, _stack);
		_handle = hookapi_hook_return(_stack[0], Win_WriteFile_Ret, this, sizeof(CWriteFile));
	}
public:
	uint32_t _stack[6];
};

struct CDeleteFile : public CBaseHook
{
public:
	CDeleteFile(string funcname):CBaseHook(funcname)
	{
		//cout<<_funcname<<endl;
		DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 2 * 4, _stack);
		if(_funcname == string("DeleteFileW"))
		{
			_handle = hookapi_hook_return(_stack[0], Win_DeleteFileW_Ret, this, sizeof(CDeleteFile));
		}
		if(_funcname == string("DeleteFileA"))
		{
			_handle = hookapi_hook_return(_stack[0], Win_DeleteFileA_Ret, this, sizeof(CDeleteFile));
		}
	}

public:
	uint32_t _stack[2];
};

#endif