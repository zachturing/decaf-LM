#ifndef _CMD_HANDLE_H
#define _CMD_HANDLE_H

void do_monitor_proc(Monitor* mon, const QDict* qdict);
void do_set_logfile1(Monitor *mon, const QDict *qdict);
void do_set_logfile2(Monitor *mon, const QDict *qdict);

void do_enable_nic(Monitor *mon);	//打开网卡监控
void do_disable_nic(Monitor *mon);  //关闭网卡监控

void do_taint_sendkey(Monitor *mon, const QDict *qdict);

void do_enable_keylogger_check( Monitor *mon, const QDict *qdict);
void do_disable_keylogger_check( Monitor *mon, const QDict *qdict);

void do_enable_search_file(Monitor *mon, const QDict *qdict);
void do_disable_search_file(Monitor*, const QDict*);

#endif