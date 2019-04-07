/*
 * @description:用于处理所有的文件操作相关的API hook
 * @date:2018.5.14
 * @author:zk
 */
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

#include "zk.h"
#include "shared/tainting/taint_info.h"

#include "apihook_file_handle.h"
#include <map>
#include <algorithm>
#include <json/json.h>
using namespace std;

extern Json::Value root;                     //
extern int getTimeStamp();

extern map<uint32_t, string> file_map;
extern vector<string> vTargetFile;
extern FILE *hook_log;

extern uint32_t targetpid;
extern uint32_t targetcr3;
extern char targetname[512];
extern uint32_t timestamp;


void addFunc(Json::Value &root, const string &procname, const Json::Value &func)
{
	int root_size = root.size();//如果两个同名的进程先后运行，则当前的func添加到后启动的进程中，所以index从root_size-1开始
    string type = func["type"].asString();

    int index = root_size - 1;
    Json::Value item = root[index];
    Json::Value::Members members = item.getMemberNames();
    Json::Value::Members::iterator it = members.begin();
    if(type == (*it)) //说明处于同一个阶段  source/propagation/leak   进一步判断是否属于同一个进程
    {
        int size = root[index][type]["proc"].size();
        int i = 0;
        for(; i < size; ++i)
        {
            //进一步判断是否属于同一个进程
            if(procname == root[index][type]["proc"][i]["@procname"].asString())
            {
                Json::Value tmp = root[index][type]["proc"][i];
                tmp["func"].append(func);
                root[index][type]["proc"][i] = tmp;   //用增加了新函数调用日志的json对象替换原来的
                return;
            }
        }
                
        if(i == size) //说明处于同一个阶段但是属于不同的进程，此时要将新进程添加进去
        {
            Json::Value proc;
            proc["@procname"] = string(targetname);
            proc["@pid"] = targetpid;
            proc["@cr3"] = targetcr3;
            proc["@timestamp"] = timestamp;
            proc["func"].append(func);
            root[index][type]["proc"].append(proc);
        }
    }
    else  //不属于同一个阶段则直接新添加  
    {
        Json::Value proc;
        proc["@procname"] = string(targetname);
        proc["@pid"] = targetpid;
        proc["@cr3"] = targetcr3;
        proc["@timestamp"] = timestamp;
        proc["func"].append(func);
        
        Json::Value period;
        period[type]["proc"].append(proc);
        root.append(period);
    } 
}

void taint_file_flush(const vector<string> &target_file)
{
     if(!target_file.empty())
     {
         ofstream outfile("/home/zk/DECAF/decaf/plugins/my_plugin/taintfile.txt");  
         for(vector<string>::iterator it = vTargetFile.begin(); it != vTargetFile.end(); ++it)
         {
             outfile<<*it<<endl;
         }
         outfile.close();         
     }    
}

void read_taint_file()
{
    if(!vTargetFile.empty())
    {
        vTargetFile.clear();
    }
    ifstream infile("/home/zk/DECAF/decaf/plugins/my_plugin/taintfile.txt");
    string line;
    while(getline(infile, line))
    {
         vTargetFile.push_back(line);
         cout<<"read_taint_file:"<<line<<endl;
    }
    infile.close();
}

void print_vector_info()
{
	cout<<"print all monitor file:"<<endl;
	for(vector<string>::iterator it = vTargetFile.begin(); it != vTargetFile.end(); ++it)
	{
		cout<<*it<<endl;		
	}
}

static uint32_t guest_wstrncpy(char *buf, size_t maxlen, gva_t vaddr) 
{
    buf[0] = 0;
    unsigned i;
    for (i = 0; i < maxlen; i++) 
    {
    	DECAF_read_mem(NULL, vaddr + 2 * i, 2, &buf[i]);
        if (buf[i] == 0) 
        {
            break;
        }
    }
    buf[maxlen - 1] = 0;
    return i;
}

static uint32_t check_virtmem(gva_t vaddr, uint32_t size)
{
	uint8_t* taint_flag = new uint8_t[size];
	memset(taint_flag, 0, size);
	int ret = taintcheck_check_virtmem(vaddr, size, taint_flag);
	if(ret != 0) 
	{
		DECAF_printf("taintcheck_check_virtmem failed.\n");
	}
	int taint_bytes = 0, i;
	for(i = 0; i < size; i++) 
		if(taint_flag[i]) 
			taint_bytes += 1;
	delete[] taint_flag;
	
	return taint_bytes;
}

void Win_OpenFile_Ret(void* params)
{
	COpenFile *p = (COpenFile*)params;
	char tmp[256];
	DECAF_read_mem(NULL, p->_stack[1], 256, tmp);
	string sFileName(tmp);
	uint32_t hfile = cpu_single_env->regs[R_EAX];  //eax寄存器存放函数的返回值，而OpenFile()的返回值为文件句柄

	if(hfile)
	{
		file_map[hfile] = sFileName;  //记录文件句柄对应的文件名
		//fprintf(hook_log, "OpenFile %s, handle: %d\n", sFileName.c_str(), hfile);
		//fflush(hook_log);
		DECAF_printf("OpenFile %s, handle: %d\n", sFileName.c_str(), hfile);
	}
	hookapi_remove_hook(p->_handle);
	delete p;
	p = NULL;
}

void Win_OpenFile_Call(void* opaque)
{
	COpenFile* params = new COpenFile("OpenFile");
}


void Win_CreateFileW_Ret(void* params)
{
	CCreateFile *p = (CCreateFile*)params;
	char tmp[256];
	guest_wstrncpy(tmp, 256, p->_stack[1]);
	string sFileName(tmp);

	uint32_t file_handle = cpu_single_env->regs[R_EAX]; //通过函数返回值获取文件句柄
	if(file_handle)
	{
		file_map[file_handle] = sFileName; //记录文件句柄对应的文件名
		//fprintf(hook_log, "CreateFileW %s, handle: %d\n", sFileName.c_str(), file_handle);
		//fflush(hook_log);
		DECAF_printf("CreateFileW %s, handle: %d\n", sFileName.c_str(), file_handle);
	}

	hookapi_remove_hook(p->_handle);
	delete p;
	p = NULL;
}

void Win_CreateFileW_Call(void* opaque)
{
	CCreateFile *params = new CCreateFile("CreateFileW");
}

void Win_CreateFileA_Ret(void* params)
{
	CCreateFile *p = (CCreateFile*)params;
	char tmp[256];
	DECAF_read_mem(NULL, p->_stack[1], 256, tmp);
	string sFileName(tmp);
	uint32_t file_handle= cpu_single_env->regs[R_EAX]; //通过函数返回值获取文件句柄
	if(file_handle)
	{
		file_map[file_handle] = sFileName;  //记录文件句柄对应的文件名	
		//fprintf(hook_log, "CreateFileW %s, handle: %d\n", sFileName.c_str(), file_handle);
		//fflush(hook_log);
		DECAF_printf("CreateFileW %s, handle: %d\n", sFileName.c_str(), file_handle);
	}
	hookapi_remove_hook(p->_handle);
	delete p;
	p = NULL;
}

void Win_CreateFileA_Call(void* opaque)
{
	CCreateFile *params = new CCreateFile("CreateFileA");
}

void Win_ReadFile_Ret(void* params)
{
	CReadFile *p = (CReadFile*)params;
	uint32_t hfile = p->_stack[1];
	string sFileName = file_map[hfile];
	uint32_t bytes_read = 0;
	DECAF_read_mem(NULL, p->_stack[4], 4, &bytes_read);
    DECAF_printf("=================================\n");
	//fprintf(hook_log, "ReadFile: filename %s %d bytes.\n", sFileName.c_str(), bytes_read);
	DECAF_printf("ReadFile: filename %s %d bytes.\n", sFileName.c_str(), bytes_read);
	
	uint32_t eip = DECAF_getPC(cpu_single_env);
	uint32_t cr3 = DECAF_getPGD(cpu_single_env);
	char name[128];
	tmodinfo_t dm;
	if(VMI_locate_module_c(eip, cr3, name, &dm) == -1)
	{
		strcpy(name, "<None>");
		bzero(&dm, sizeof(dm));
	}

	for(vector<string>::iterator it = vTargetFile.begin(); it != vTargetFile.end(); ++it)
	{
		string target_file = *it;
		if(sFileName.rfind(target_file) == sFileName.length() - target_file.length())
		{
			uint8_t *taint_flag = new uint8_t[bytes_read];
			memset((void*)taint_flag, 0xff, bytes_read);
			taintcheck_taint_virtmem(p->_stack[2], bytes_read, taint_flag);
			delete[] taint_flag;
			taint_flag = NULL;

			int taint_bytes = check_virtmem(p->_stack[2], p->_stack[3]);
			//fprintf(hook_log, "ReadFile: read content tainted %d bytes.\n", bytes_read); //0528
	
			if(0 != bytes_read)
			{
	 			Json::Value funcInfo;
                funcInfo["type"] = string("taint_propagation");
	            funcInfo["timestamp"] = getTimeStamp();		
				funcInfo["call_addr"] = eip;
				funcInfo["op_type"] = "file";
				funcInfo["func_name"] = "ReadFile";
				funcInfo["file_name"] = sFileName;
				funcInfo["file_handle"] = hfile;
				funcInfo["addr"] = p->_stack[2];   //buf
				funcInfo["len"] = bytes_read;
                cout<<funcInfo.toStyledString()<<endl;
				addFunc(root, name, funcInfo);
			}
			

			DECAF_printf("ReadFile: read content tainted %d bytes.\n", bytes_read);

			break;
		}
	}
	//fflush(hook_log);   //0528

    DECAF_printf("=================================\n");
	hookapi_remove_hook(p->_handle);
	delete p;
	p = NULL;
}

void Win_ReadFile_Call(void* opaque)
{
	CReadFile *params = new CReadFile("ReadFile");
}

void Win_WriteFile_Ret(void* params)
{
	CWriteFile *p = (CWriteFile*)params;
	uint32_t hfile = p->_stack[1];
	string sFileName = file_map[hfile];
    DECAF_printf("=================================\n");
	int taint_bytes = check_virtmem(p->_stack[2], p->_stack[3]);
	if(taint_bytes <= 0)   //写入的内容中没有打上污点标签直接返回
	{
		return;
	}

    Json::Value funcInfo;
    vector<string>::iterator it = find(vTargetFile.begin(), vTargetFile.end(), sFileName);
	if(it == vTargetFile.end())  //如果被写入的文件中的内容没有打上污点标签而且还没放入监控文件队列中，将加入监控文件队列
	{
		vTargetFile.push_back(sFileName);
        //污点数据被写入新文件中则表示发生泄漏
        funcInfo["type"] = string("taint_leak");
#ifdef ZK
        taint_file_flush(vTargetFile);     
#endif /* ZK */	
    }
    else
    {//如果污点数据还是被写入原来的文件，仍然是一次污点传播
        funcInfo["type"] = string("taint_propagation");
    }

	uint32_t eip = DECAF_getPC(cpu_single_env);
	uint32_t cr3 = DECAF_getPGD(cpu_single_env);
	char name[128];
	tmodinfo_t dm;
	if(VMI_locate_module_c(eip, cr3, name, &dm) == -1)
	{
		strcpy(name, "<None>");
		bzero(&dm, sizeof(dm));
	}
	if(taint_bytes) 
	{
		//fprintf(hook_log, "Process %s WriteFile: filename=%s write %d bytes tainted memory!\n", name, sFileName.c_str(), taint_bytes);   //0528
		//fflush(hook_log);		//0528
		DECAF_printf("Process %s WriteFile: filename=%s write %d bytes tainted memory!\n", name, sFileName.c_str(), taint_bytes);
				
	    funcInfo["timestamp"] = getTimeStamp();		
		funcInfo["call_addr"] = eip;
		funcInfo["op_type"] = "file";
		funcInfo["func_name"] = "WriteFile";
		funcInfo["file_name"] = sFileName;
		funcInfo["file_handle"] = hfile;
		funcInfo["addr"] = p->_stack[2];   //buf
		funcInfo["len"] = taint_bytes;
	    cout<<funcInfo.toStyledString()<<endl;
		addFunc(root, name, funcInfo);
				
	}
    DECAF_printf("------------------------------\n");
	hookapi_remove_hook(p->_handle);
	delete p;
	p = NULL;
}

void Win_WriteFile_Call(void* )
{
	CWriteFile *params = new CWriteFile("WriteFile");
}

void Win_DeleteFileA_Ret(void* params)
{
	CDeleteFile *p = (CDeleteFile*)params;
	char tmp[256];
	DECAF_read_mem(NULL, p->_stack[1], 256, tmp);
	string sFileName(tmp);
	//fprintf(hook_log, "DeleteFileA: filename %s.\n", sFileName.c_str());  //0528
	//fflush(hook_log);	//0528
	DECAF_printf("DeleteFileA: filename %s.\n", sFileName.c_str());
	hookapi_remove_hook(p->_handle);
	delete p;
	p = NULL;
}

void Win_DeleteFileA_Call(void* opaque)
{
	CDeleteFile *params = new CDeleteFile("DeleteFileA");
}

void Win_DeleteFileW_Ret(void* params)
{
	CDeleteFile *p = (CDeleteFile*)params;
	char filename[256];
	guest_wstrncpy(filename, 256, p->_stack[1]);
	string sFileName(filename);
	//DECAF_read_mem(NULL, p->_stack[1], 256 , filename);
	//fprintf(hook_log, "DeleteFileW: filename %s.\n", filename);  //0528
	//fflush(hook_log);	//0528
	DECAF_printf("DeleteFileW: filename %s.\n", sFileName.c_str());
	hookapi_remove_hook(p->_handle);
	delete p;
	p = NULL;
}

void Win_DeleteFileW_Call(void* opaque)
{
	CDeleteFile *params = new CDeleteFile("DeleteFileW");
}

void Win_MoveFileAll_Ret(void* opaque)
{
	CMoveFile *p = (CMoveFile*)opaque;
	char sExistingFileName[256];
	char sNewFileName[256];
	cout<<"========================================="<<endl;
	DECAF_printf("%s\n", p->_funcname.c_str());
	
	if(p->_funcname.c_str() == string("MoveFileWithProgressW"))
	{
		guest_wstrncpy(sExistingFileName, 256, p->_stack[1]);
		guest_wstrncpy(sNewFileName, 256, p->_stack[2]);
	}
    else
	{
		DECAF_read_mem(NULL, p->_stack[1], 256, sExistingFileName);
		DECAF_read_mem(NULL, p->_stack[2], 256, sNewFileName);
	}
	//fprintf(hook_log, "Existing file name:%s\n", sExistingFileName);  //0528
	//fprintf(hook_log, "New file name:%s\n", sNewFileName);			  //0528
	DECAF_printf("Existing file name:%s\n", sExistingFileName);
	DECAF_printf("New file name:%s\n", sNewFileName);

	vector<string>::iterator it = find(vTargetFile.begin(), vTargetFile.end(), sExistingFileName);

	if(vTargetFile.end() != it)  //重命名了监控的目标文件
	{
		//fprintf(hook_log, "========================\n");	//0528
		//cout<<"================"<<endl;
		*it = sNewFileName;   //对于改名，直接替换原来的文件名
		//DECAF_printf("New target file name:%s\n", it->c_str());

		uint32_t eip= DECAF_getPC(cpu_single_env);
		uint32_t cr3= DECAF_getPGD(cpu_single_env);
		char name[128];   //进程名
		tmodinfo_t dm;
		if(VMI_locate_module_c(eip,cr3, name, &dm) == -1)
		{
			strcpy(name, "<None>");
			bzero(&dm, sizeof(dm));
		}
		else
		{	
			//fprintf(hook_log,  "module name:%s\n", dm.name);  //0528
			//fprintf(hook_log, "Process %s in function %s:change the file name to %s\n", name, p->_funcname.c_str(), sNewFileName); //0528
			DECAF_printf("module name:%s\n", dm.name);
			DECAF_printf("Process %s in function %s:change the file name to %s\n", name, p->_funcname.c_str(), sNewFileName);
		}

#ifdef ZK
        taint_file_flush(vTargetFile);

        Json::Value funcInfo;

        funcInfo["type"] = string("taint_propagation");
	    funcInfo["timestamp"] = getTimeStamp();		
	    funcInfo["call_addr"] = eip;
	    funcInfo["op_type"] = "file";
	    funcInfo["func_name"] = "MoveFile";		
        funcInfo["existing_filename"] = sExistingFileName;
        funcInfo["new_filename"] = sNewFileName;
	    cout<<funcInfo.toStyledString()<<endl;	
		addFunc(root, name, funcInfo);

#endif /* ZK */
	}	
	else
	{
		//fprintf(hook_log, "========================\n");	//0528
		cout<<"no found target file"<<endl;
	}	
	//fflush(hook_log);
    cout<<"-------------------------------------------"<<endl;
	hookapi_remove_hook(p->_handle);
	delete p;
	p = NULL;
}

void Win_MoveFileA_Call(void* opaque)
{
	CMoveFile* params = new CMoveFile("MoveFileA");
}

void Win_MoveFileW_Call(void* opaque)
{
	CMoveFile* params = new CMoveFile("MoveFileW");
}

void Win_MoveFileExA_Call(void* opaque)
{
	CMoveFile* params = new CMoveFile("MoveFileExA");
}

void Win_MoveFileExW_Call(void* opaque)
{
	CMoveFile* params = new CMoveFile("MoveFileExW");
}

void Win_MoveFileWithProgressA_Call(void* opaque)
{
	CMoveFile* params = new CMoveFile("MoveFileWithProgressA");
}

void Win_MoveFileWithProgressW_Call(void* opaque)
{
	CMoveFile* params = new CMoveFile("MoveFileWithProgressW");
}

void Win_MoveFileTransactedA_Call(void* opaque)
{
	CMoveFile* params = new CMoveFile("MoveFileTransactedA");
}

void Win_MoveFileTransactedW_Call(void* opaque)
{
	CMoveFile* params = new CMoveFile("MoveFileTransactedW");
}
