{
	"do_set_logfile1",
	"logfile:F?",
	"[logfile]",
	"specify the log file [logfile]",
	NULL,
	(void (*)(Monitor*))do_set_logfile1,
},
{
	"do_set_logfile2",
	"logfile:F?",
	"[logfile]",
	"specify the log file [logfile]",
	NULL,
	(void (*)(Monitor*))do_set_logfile2,
},
{
	"taint_sendkey",
	"key:s",
	"[key]",
	"send a tainted key to the guest system",
	NULL,
	(void (*)(Monitor*))do_taint_sendkey
}, //nic
{
	"do_enable_nic",
	"",
	"",
	"enable nic monitor",
	NULL,
	do_enable_nic,
},
{
	"do_disable_nic",
	"",
	"",
	"disable nic monitor",
	NULL,
	do_disable_nic,
}, //keylogger
{
	"do_monitor_proc",
	"procname:s?",
	"[procname]",
	"Run the tests with program [procname]",
	NULL,
	(void (*)(Monitor*))do_monitor_proc,
},
{
	"enable_keylogger_check",
	"tracefile:F",
	"[trace_file name]",
	"check every tainted instruction to see what module it belongs to ",
	NULL,
	(void (*)(Monitor*))do_enable_keylogger_check,
},
{
	"disable_keylogger_check",
	"",
	"[no params]",
	"disable function that check every tainted instruction to see what module it belongs to",
	NULL,
	(void (*)(Monitor*))do_disable_keylogger_check,
},//string search
{   
    "enable_search_file",       
    "filename:F",     
    "[search string file name]",
    "指定存放搜索串的文件名",
    NULL,
    (void (*)(Monitor*))do_enable_search_file
},
{   
    "disable_search_file",       
    "",     
    "[no params]",
    "disable search file",
    NULL,
    (void (*)(Monitor*))do_disable_search_file
},