#ifndef _NIC_HANDLE_H_
#define _NIC_HANDLE_H_

void PrintInfo();
void nic_cleanup();
void tracing_nic_recv(DECAF_Callback_Params* params);
void tracing_nic_send(DECAF_Callback_Params* params);

#endif