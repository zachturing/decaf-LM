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

typedef struct _callbacktest_t
{
  char name[64];
  DECAF_callback_type_t cbtype;
  DECAF_Handle handle;
}callbacktest_t;


void Y_ins_hook(uint32_t targetcr3);
void Y_ins_unhook();

static callbacktest_t Y_Ins_Hook={"Insn Begin", DECAF_INSN_BEGIN_CB, DECAF_NULL_HANDLE};
static uint32_t Y_ins_cr3;

static int Y_cmp_ins(unsigned char * ins_code){
      csh handle;
      cs_insn *insn;
      size_t count;
     
      char * ins_list[]={"in","sidt","sldt","sgdt","smsw","cpuid"};
      if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)return -1;
      count = cs_disasm(handle, ins_code, sizeof(ins_code)-1, 0x1000, 0, &insn);
      if (count > 0) {
           // size_t i;
            //for(i=0;i<sizeof(ins_list)/sizeof(char*);i++){
                //if(strcmp(insn[0].mnemonic,ins_list[i])==0){
            if(strcmp(insn[0].mnemonic,"in")==0 && cpu_single_env->regs[R_EAX]==0x564d5868)DECAF_printf("suspicious ins call--in,eax=%x\n",0x564d5868);
                    //if(strcmp(ins_list[i],"")!=0)DECAF_printf("suspicious ins call--%s\n",ins_list[i]);
                  //  break;
                //}
            }
         cs_free(insn, count);
     cs_close(&handle);
     return 0;
}


static void Y_callback_ins_begin(DECAF_Callback_Params* param)
{
    if(param==0)return; 
    CPUState* env = param->ib.env;
    uint32_t thiscr3=DECAF_getPGD(env);
    if(Y_ins_cr3!=thiscr3 && DECAF_is_in_kernel(env)==0)return;
    
    unsigned char insn_buf[64]={0};

    DECAF_read_mem(env, env->eip, 64, insn_buf);    
    Y_cmp_ins(insn_buf);
}

void Y_ins_hook(uint32_t targetcr3)
{
  Y_Ins_Hook.handle=DECAF_register_callback(Y_Ins_Hook.cbtype, &Y_callback_ins_begin,NULL);
    if (Y_Ins_Hook.handle == DECAF_NULL_HANDLE)
    {
      DECAF_printf("Could not registe the event\n");
      return; 
    }

  Y_ins_cr3=targetcr3;
}

void Y_ins_unhook()
{
  if(Y_Ins_Hook.handle != DECAF_NULL_HANDLE)
  {
    DECAF_unregister_callback(Y_Ins_Hook.cbtype, Y_Ins_Hook.handle);
    Y_Ins_Hook.handle = DECAF_NULL_HANDLE;
  } 
}
