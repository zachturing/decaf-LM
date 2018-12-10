#ifndef _KEYLOGGER_HANDLE_H_
#define _KEYLOGGER_HANDLE_H_

void check_call(DECAF_Callback_Params *param);
void check_ret(DECAF_Callback_Params *param);
void do_read_taint_mem(DECAF_Callback_Params *param);
void do_write_taint_mem(DECAF_Callback_Params *param);
void keylogger_cleanup();
void do_block_end_cb(DECAF_Callback_Params *param);
void tracing_send_keystroke(DECAF_Callback_Params *params);

#endif