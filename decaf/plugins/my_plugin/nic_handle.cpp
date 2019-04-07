#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifdef CONFIG_TCG_TAINT
#include "tainting/taintcheck_opt.h"
#endif

#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <json/json.h>

using namespace std;

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

#include "nic_handle.h"
#include "apihook_file_handle.h"
extern Json::Value root;
extern uint32_t targetpid;
extern uint32_t targetcr3;
extern char targetname[512];
extern uint32_t timestamp;
extern vector<string> vTargetFile;
extern DECAF_Handle nic_rec_cb_handle;
extern DECAF_Handle nic_send_cb_handle;
extern FILE *nic_log;
extern void addFunc(Json::Value &root, const string &procname, const Json::Value &func);

/*static void addFunc(Json::Value &root, const string &procname, const Json::Value &func)
{
        int size = root["taint_propagation"]["proc"].size();
        for(int i = 0; i < size; ++i)
        {
                //strcasecmp()
                if(procname == root["taint_propagation"]["proc"][i]["@procname"].asString())
                {
                        Json::Value tmp = root["taint_propagation"]["proc"][i];
                        tmp["func"].append(func);
                        root["taint_propagation"]["proc"][i] = tmp;
                        break;
                }
        }
}
*/
static int nic_check_virtmem(const uint32_t addr, const int size)
{
	uint8_t *taint_flag = new uint8_t[size];
	memset(taint_flag, 0, size);
	taintcheck_nic_readbuf(addr, size, taint_flag);
	int tainted_bytes = 0, i;
	for(i = 0; i < size; ++i)
	{
		if(taint_flag[i])
		{
			++tainted_bytes;
		}
	}
	delete[] taint_flag;
	taint_flag = NULL;
	return tainted_bytes;
}

void nic_cleanup()
{
	DECAF_printf("nic_cleanup.\n");

	if(nic_log)
	{
		fclose(nic_log);
		nic_log = NULL;
	}
	if (nic_rec_cb_handle != DECAF_NULL_HANDLE)
	{
		DECAF_unregister_callback(DECAF_NIC_REC_CB, nic_rec_cb_handle);
		nic_rec_cb_handle = DECAF_NULL_HANDLE;
	}

	if (nic_send_cb_handle != DECAF_NULL_HANDLE)
	{
		DECAF_unregister_callback(DECAF_NIC_SEND_CB, nic_send_cb_handle);
		nic_send_cb_handle = DECAF_NULL_HANDLE;
	}
}

void tracing_nic_recv(DECAF_Callback_Params* params)
{
	//DECAF_printf("tracing_nic_recv.\n");
}


void tracing_nic_send(DECAF_Callback_Params* params)
{
	uint32_t eip = DECAF_getPC(cpu_single_env);
    uint32_t cr3 = DECAF_getPGD(cpu_single_env);
    char name[128];
    tmodinfo_t dm;
    if(VMI_locate_module_c(eip, cr3, name, &dm) == -1)
    {
        strcpy(name, "<None>");
        bzero(&dm, sizeof(dm));
    }


	//DECAF_printf("tracing_nic_send:\n");
	uint32_t addr = params->ns.addr;
	int size = params->ns.size;
	uint8_t * buf = params->ns.buf;
	vector<char> vTaintedData;
	//uint32_t conn_id = 0;
	//DECAF_printf("addr:%x\n", addr);
	//DECAF_printf("buf:%x\n", buf);
	//DECAF_printf("size: %d\n", size);  //报文传输长度，如果不满60个字节则会进行填充
	if ( (buf == NULL) || (size == 0) )
		return;

//判断大小端
/*
#ifdef HOST_WORDS_BIGENDIAN
	DECAF_printf("HOST_WORDS_BIGENDIAN\n");
#else
	DECAF_printf("little endian\n");
#endif
*/

	//获取ip头部信息
	if( (buf[12] != 0x08) || (buf[13] != 0) ) // Ignore non-IP packets 
	{
		//DECAF_printf("the upper layer isn't IP protocol.\n");
		return;
	}


	struct ip *iph = (struct ip *)(buf + 14);
	if( (iph->ip_p != 6) && (iph->ip_p != 17) )   // Ignore non TCP/UDP segments
	{
		return;
	}

	struct tcphdr *tcph = (struct tcphdr *)(buf + 34);
	struct udphdr *udph = (struct udphdr *)(buf + 34);

	//DECAF_printf("the newtwork layer is IP protocol.\n");
	
	const char* ip_src = inet_ntoa(iph->ip_src);  //源IP地址
	const char* ip_dst = inet_ntoa(iph->ip_dst);  //目的IP地址

	int iIPHeadLen = iph->ip_hl * 4;   /* IP头部长度 */

	int iTotalLen = ntohs(iph->ip_len) + 14;    //报文实际总长度   ip_len是ip报文的总长度
	int iHeadLen;     //帧头+IP头+TCP/UDP头
	int iDataLen;     //数据部分长度

	if(6 == iph->ip_p) /* TCP */
	{
		//DECAF_printf("The transport layer is TCP protocol.\n");
		int iTCPHeadLen = tcph->th_off * 4;
		iHeadLen = 14 + iIPHeadLen + iTCPHeadLen;
		iDataLen = iTotalLen - iHeadLen;   			  //数据字节数
		uint32_t sport = ntohs(tcph->th_sport);		  //源端口号	
		uint32_t dport = ntohs(tcph->th_dport);	      //目的端口号
		//DECAF_printf("%s：%d --> %s：%d\n", ip_src, sport, ip_dst, dport);
		//DECAF_printf("帧头部 ：14 bytes.\n");
		//DECAF_printf("IP头部 ：%d bytes.\n", iIPHeadLen);
		//DECAF_printf("TCP头部：%d bytes.\n", iTCPHeadLen);
		//DECAF_printf("数据   ：%d bytes.\n", iDataLen);

		if(iDataLen > 0)
		{
			//只输出被打上污点标签的数据
			/*uint8_t *taint_flag = new uint8_t[size];
			memset(taint_flag, 0, size);
			taintcheck_nic_readbuf(addr, size, taint_flag);*/

			uint8_t *taint_flag = new uint8_t[iDataLen];
			memset(taint_flag, 0, iDataLen);
			taintcheck_nic_readbuf(addr + iHeadLen, iDataLen, taint_flag);  //从报文的数据部分开始检测污染状况

			int tainted_bytes = 0;
			int i;
			for(i = 0; i < iDataLen; ++i)
			{
				if(taint_flag[i])
				{
					vTaintedData.push_back(*((char*)buf + iHeadLen + i));  //记录打上污点标签的数据
					++tainted_bytes;    						//统计污点内存字节数
				}
			}

			/*   //这里是输出所有数据
			int i = 0;
			for(; i < iDataLen; ++i)
			{
				//DECAF_printf("%c ", *((char*)buf + iHeadLen + i));
				fprintf(nic_log, "%c ", *((char*)buf + iHeadLen + i));
			}
			//DECAF_printf("\n");
			*/
			if(tainted_bytes > 0)  //只输出报文中的污点数据
			{
				fprintf(nic_log, "%s：%d --> %s：%d\n", ip_src, sport, ip_dst, dport); //0528
				fprintf(nic_log, "%-10s %-10s %-10s %-10s    (单位:byte)\n", "帧头部", "IP头部", "TCP头部", "数据");
				fprintf(nic_log, "  %d     %d       %d      %d          \n", 14, iIPHeadLen, iTCPHeadLen, iDataLen);
				fprintf(nic_log, "发送的污点数据：\n");
				for(int i = 0; i < vTaintedData.size(); ++i)
				{
					fprintf(nic_log, "%c ", vTaintedData[i]);
				}				
				fprintf(nic_log, "\n");
				fprintf(nic_log, "send tainted bytes is %d.\n\n", tainted_bytes);
			    
                Json::Value proc;
                proc["@procname"] = targetname;
                proc["@pid"] = targetpid;
                proc["@cr3"] = targetcr3;
                proc["@timestamp"] = timestamp;
                Json::Value period;
                period["taint_leak"]["proc"].append(proc);

				Json::Value funcInfo;
                funcInfo["type"] = string("taint_leak");
				funcInfo["op_type"] = "socket";
				funcInfo["func_name"] = "send";
				funcInfo["proto_type"] = "TCP";
				funcInfo["source_ip"] = string(ip_src);
				funcInfo["source_port"] = sport;
				funcInfo["dest_ip"] = string(ip_dst);
				funcInfo["dest_port"] = dport;
				funcInfo["tainted_bytes"] = tainted_bytes;
				//cout<<funcInfo.asString()<<endl;
				addFunc(root, name, funcInfo);
			}
			delete[] taint_flag;   //以免发生内存泄露
		}		
		//int tainted_bytes = nic_check_virtmem(addr, size);//检测整个报文中有多少污点内存
		//DECAF_printf("send tainted bytes is %d.\n\n", tainted_bytes);
		//fprintf(nic_log, "send tainted bytes is %d.\n\n", tainted_bytes);
	} 
	else if(17 == iph->ip_p)	/* UDP */
	{
		//DECAF_printf("The transport layer is UDP protocol.\n");
		iHeadLen = 14 + iIPHeadLen + 8;   //UDP头部为固定的8字节
		iDataLen = iTotalLen - iHeadLen;  //数据长度
		uint32_t sport = ntohs(udph->uh_sport);		  //源端口号	
		uint32_t dport = ntohs(udph->uh_dport);	      //目的端口号
		//DECAF_printf("%s：%d --> %s：%d\n\n", ip_src, sport, ip_dst, dport);
		//DECAF_printf("帧头部 ：14 bytes.\n");
		//DECAF_printf("IP头部 ：%d bytes.\n", iIPHeadLen);
		//DECAF_printf("UDP头部： 8 bytes.\n");
		//DECAF_printf("数据   ：%d bytes.\n", iDataLen);
				
		if(iDataLen > 0)
		{			
			/*uint8_t *taint_flag = new uint8_t[size];
			memset(taint_flag, 0, size);
			taintcheck_nic_readbuf(addr, size, taint_flag);*/
			uint8_t *taint_flag = new uint8_t[iDataLen];
			memset(taint_flag, 0, iDataLen);
			taintcheck_nic_readbuf(addr + iHeadLen, iDataLen, taint_flag);
			int tainted_bytes = 0;
			int i;
			for(i = 0; i < iDataLen; ++i)
			{
				if(taint_flag[i])
				{
					vTaintedData.push_back(*((char*)buf + iHeadLen + i));					
					++tainted_bytes;
				}
			}
			/*
			int i = 0;  //输出报文中的所有数据
			for(; i < iDataLen; ++i)
			{
				//DECAF_printf("%c ", *((char*)buf + iHeadLen + i));
				fprintf(nic_log, "%c ", *((char*)buf + iHeadLen + i));
			}
			//DECAF_printf("\n");
			*/
			if(tainted_bytes > 0)  //只输出报文中的污点数据
			{
				fprintf(nic_log, "%s：%d --> %s：%d\n", ip_src, sport, ip_dst, dport); //0528
				fprintf(nic_log, "%-10s %-10s %-10s %-10s    (单位:byte)\n", "帧头部", "IP头部", "UDP头部", "数据");
				fprintf(nic_log, "  %d     %d       %d      %d          \n", 14, iIPHeadLen, 8, iDataLen);
				fprintf(nic_log, "发送的污点数据：\n");
				for(int i = 0; i < vTaintedData.size(); ++i)
				{
					fprintf(nic_log, "%c ", vTaintedData[i]);
				}				
				fprintf(nic_log, "\n");
				fprintf(nic_log, "send tainted bytes is %d.\n\n", tainted_bytes);
			
				Json::Value funcInfo;
				funcInfo["op_type"] = "socket";
				funcInfo["func_name"] = "send";
				funcInfo["proto_type"] = "UDP";
				funcInfo["source_ip"] = string(ip_src);
				funcInfo["source_port"] = sport;
				funcInfo["dest_ip"] = string(ip_dst);
				funcInfo["dest_port"] = dport;
				funcInfo["tainted_bytes"] = tainted_bytes;
				addFunc(root, name, funcInfo);
				
			}			
			delete[] taint_flag; 
		}		
		//int tainted_bytes = nic_check_virtmem(addr, size);//检测整个报文中有多少污点内存
		//DECAF_printf("send tainted bytes is %d.\n\n", tainted_bytes);
	}
	fflush(nic_log);
	return;
}
