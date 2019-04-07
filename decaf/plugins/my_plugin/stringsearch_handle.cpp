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

#include "stringsearch_handle.h"
#include <cstdio>
#include <cstdlib>
#include <ctype.h>
#include <cmath>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
using namespace std;

extern DECAF_Handle mem_read_handle;
extern DECAF_Handle mem_write_handle;
extern FILE *stringsearch_log;

uint8_t  tofind[MAX_STRINGS][MAX_STRLEN];
uint32_t strlens[MAX_STRINGS];
char     buf[MAX_SEARCH_LEN]; 		
int      num_strings = 0;
int      n_callers = 16;

char target_file_name[512];

struct string_pos 
{
    uint32_t val[MAX_STRINGS];
    string_pos()
    {
        int i = 0;
        for(; i < MAX_STRINGS; ++i)
        {
            val[i] = 0;
        }
    	//bzero(val, sizeof(val));
    }
};

void stringsearch_cleanup()
{
	DECAF_printf("stringsearch_cleanup.\n");
	if(stringsearch_log != NULL)
	{
		fclose(stringsearch_log);
		stringsearch_log = NULL;
		DECAF_printf("close file stringsearch_log.\n");
	}
	if(mem_read_handle != DECAF_NULL_HANDLE)
	{
		DECAF_unregister_callback(DECAF_MEM_READ_CB, mem_read_handle);
		mem_read_handle = NULL;
	}
	if(mem_write_handle != DECAF_NULL_HANDLE)
	{
		DECAF_unregister_callback(DECAF_MEM_WRITE_CB, mem_write_handle);
		mem_write_handle = NULL;
	}
}

int mem_callback(void *buf, int size, bool is_write, int *pMatchLen)
{  
	//DECAF_printf("mem_callback.\n");
	string_pos sp;
	int offset = -1;
	for (unsigned int i = 0; i < size; i++)   //size为buf中的有效匹配长度
	{
        uint8_t val = ((uint8_t *)buf)[i];
        for(int str_idx = 0; str_idx < num_strings; str_idx++)
        {
            if (tofind[str_idx][sp.val[str_idx]] == val)
            {
                sp.val[str_idx]++;
            }
            else
            {
                sp.val[str_idx] = 0;
            }

            if (sp.val[str_idx] == strlens[str_idx])  //第str_idx个字符串匹配成功
            {
                // Victory!
                //DECAF_printf("%s Match of str %s\n", (is_write ? "WRITE" : "READ"), tofind[str_idx]);                
                fprintf(stringsearch_log, "%s Match of str %s\n", (is_write ? "WRITE" : "READ"), tofind[str_idx]);
                //fprintf(stringsearch_log, "addr:0x%x\n", (uint8_t*)buf + i - strlens[str_idx] + 1);  //这里加1，原因在于i是从0开始的，或者说字符数组的下标是从0开始的
                *pMatchLen = strlens[str_idx];   //记录当前匹配的字符串的长度

		int k = 0;
		for(; k < *pMatchLen; ++k)
		{
                        printf("%d:%c--%d.\n", k, tofind[str_idx][k], tofind[str_idx][k]);
			fprintf(stringsearch_log, "%c.", tofind[str_idx][k]);
		}
	
                fprintf(stringsearch_log, "\n match string len is %d.\n", *pMatchLen);

               // int index = 1;
               // for(; index <= strlens[str_idx]; ++index)
               // {
               // 	fprintf(stringsearch_log, "0x%x:%c\n", (char*)buf + i - strlens[str_idx] + index, *((char*)buf + i - strlens[str_idx] + index));
               // }
 
               // fprintf(stringsearch_log, "%s\n\n", "Victory");
                fflush(stringsearch_log);
                sp.val[str_idx] = 0;
                offset = i;
                break;
            }
        }
    }
    return offset;
}

/*
 * @function name:parse_file
 * @function:解析存放待搜索字符串的文件.字符串包括两种，同panda
 * @params:
	stringsfile:存放待搜索字符串的文件名
 * @return:正确解析返回true,反之返回false
 */
bool parse_file(const char* stringsfile)
{
	ifstream search_strings(stringsfile);
	if(!search_strings)
	{
		DECAF_printf("Couldn't open %s; no strings to search for. Exiting.\n", stringsfile);
		return false;
	}

	string line;
	while(getline(search_strings, line))
	{
		DECAF_printf("line:%s\n", line.c_str());
		istringstream iss(line);
		if(line[0] == '"')  //解析 " xxx " 双引号括起来的字符串
		{
			size_t len = line.size() - 2;  //获取字符串的长度
			memcpy(tofind[num_strings], line.substr(1, len).c_str(), len);
			strlens[num_strings] = len;
			printf("%s\n", tofind[num_strings]);
		} 
		else  //解析以":"分隔的十六进制字节序列
		{
			string x;
			int i = 0;
			while(getline(iss, x, ':'))
			{
				tofind[num_strings][i++] = (uint8_t)strtoul(x.c_str(), NULL, 16);
				printf("%x", tofind[num_strings][i - 1]);
				if(i >= MAX_STRLEN)
				{
                                    printf("WARN: Reached max number of characters (%d) on string %d, truncating.\n", MAX_STRLEN, num_strings);
                                    break;
                                }                
			}
			strlens[num_strings] = i;
			printf("\n");
		}
		

	    DECAF_printf("stringsearch: added string of length %d to search set\n", strlens[num_strings]);

        if(++num_strings >= MAX_STRINGS) 
        {  //最多搜索MAX_STRINGS个字符序列，这里定义的是100
            DECAF_printf("WARN: maximum number of strings (%d) reached, will not load any more.\n", MAX_STRINGS);
            break;
        }
	}
	search_strings.close();
	return true;
}

void do_mem_read_cb(DECAF_Callback_Params *param)
{
	//DECAF_printf("do_mem_read_cb.\n");
	CPUState *env=param->be.env;
	if(env == NULL)
	{
		DECAF_printf("env is NULL\n");
		return;
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


	for(int i = 0; i < PROC_NUM; ++i)
	{ 
		if(strcmp(name, procname[i]) == 0)  //通过进程名进行过滤，说明触发此回调函数的进程是我们所关注的进程
		{			
			//DECAF_read_mem_with_pgd(cpu_single_env, cr3, param->mr.vaddr, MAX_SEARCH_LEN, (void*)buf);
		//	DECAF_printf("process %s is searching.\n", name);	
			CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
			DECAF_physical_memory_rw(cpu_single_env, param->mr.paddr, (uint8_t*)buf, MAX_SEARCH_LEN, 0);

			int bytes_read = 0;
			int offset = mem_callback(buf, MAX_SEARCH_LEN, false, &bytes_read);   //返回匹配的最后的一个字符的位置，bytes_read也是字符串的长度
			if(offset != -1)
			{
				printf("search success.\n");

				fprintf(stringsearch_log, "%s:\n", name);
				fprintf(stringsearch_log, "proc name :%s   offset :%d   tainted bytes :%d\n", name, offset + 1, bytes_read);   //因为下标从0开始，所以表示位置时要加1
				
				uint8_t* taint_flag= new uint8_t[bytes_read];
				memset((void*)taint_flag, 0xff, bytes_read);
				//打上污点标签  
				taintcheck_taint_virtmem(param->mr.vaddr + offset - bytes_read + 1, bytes_read, taint_flag);
				
				fprintf(stringsearch_log, "paddr: 0x%x\n", DECAF_get_phys_addr(env, param->mr.vaddr + offset - bytes_read + 1));
				fflush(stringsearch_log);
				//fprintf(stringsearch_log, "vaddr:0x%x\n", param->mr.vaddr + offset - STRING_LEN);
				//fprintf(stringsearch_log, "vaddr->paddr:%x\n", DECAF_get_phys_addr(cpu_single_env, param->mr.vaddr + offset - STRING_LEN));
				//fprintf(stringsearch_log, "guest os virtual address:%x\n", cpu_single_env->regs[R_EBP]);
				delete[] taint_flag;
				break;
			}
			else
			{
				//printf("search failed.\n");
			}
		}
	}
}


void do_mem_write_cb(DECAF_Callback_Params *param)
{
	//DECAF_printf("do_mem_write_cb.\n");
	CPUState *env=param->be.env;
	if(env == NULL)
	{
		DECAF_printf("env is NULL\n");
		return;
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

	for(int i = 0; i < PROC_NUM; ++i)
	{ 
		if(strcmp(name, procname[i]) == 0)  //说明触发此回调函数的进程是我们所关注的进程
		{			
			//DECAF_printf("process %s is searching.\n", name);	
			//DECAF_read_mem_with_pgd(cpu_single_env, cr3, param->mr.vaddr, MAX_SEARCH_LEN, (void*)buf);
			CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
			DECAF_physical_memory_rw(cpu_single_env, param->mr.paddr, (uint8_t*)buf, MAX_SEARCH_LEN, 0);

			int bytes_read = 0;
			int offset = mem_callback(buf, MAX_SEARCH_LEN, true, &bytes_read);
			if(offset != -1)
			{
				printf("search success.\n");
				fprintf(stringsearch_log, "%s:\n", name);
				fprintf(stringsearch_log, "proc name :%s   offset :%d   tainted bytes :%d\n", name, offset + 1, bytes_read);
				
				uint8_t* taint_flag= new uint8_t[bytes_read];
				memset((void*)taint_flag, 0xff, bytes_read);
				taintcheck_taint_virtmem(param->mr.vaddr + offset - bytes_read + 1, bytes_read, taint_flag);

				CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
				fprintf(stringsearch_log, "paddr: 0x%x\n", DECAF_get_phys_addr(env, param->mr.vaddr + offset - bytes_read + 1));

				//fprintf(stringsearch_log, "vaddr:0x%x\n", param->mr.vaddr);
				//fprintf(stringsearch_log, "paddr:0x%x\n", param->mr.paddr);
				fflush(stringsearch_log);
				delete[] taint_flag;
				break;
			}
			else
			{
				//printf("search failed.\n");
			}
		}
	}
}
