#include "DECAF_types.h" 
#include "DECAF_main.h" 
#include "DECAF_callback.h" 
#include "DECAF_callback_common.h" 
#include "vmi_callback.h" 
#include "utils/Output.h" 
#include "DECAF_target.h"

static plugin_interface_t plugin_interface;

void plugin_cleanup()
{
	 DECAF_printf("Bye Bye.\n");
}


void do_set_logfile1(Monitor *mon, const QDict *qdict)
{
	const char *logfile_t = qdict_get_str(qdict, "logfile");
	DECAF_printf("%s\n", logfile_t);
}

void do_set_logfile2(Monitor *mon, const QDict *qdict)
{
	const char *logfile_t = qdict_get_str(qdict, "logfile");
	DECAF_printf("%s\n", logfile_t);
}

static mon_cmd_t plugin_term_cmds[] = {
	{
		.name		= "do_set_logfile1",
		.args_type	= "logfile:F?",
		.mhandler.cmd	= do_set_logfile1,
		.params		= "[logfile]",
		.help		= "specify the log file [logfile]",
	},
	{
		.name		= "do_set_logfile2",
		.args_type	= "logfile:F?",
		.mhandler.cmd	= do_set_logfile2,
		.params		= "[logfile]",
		.help		= "specify the log file [logfile]",
	}
};


plugin_interface_t* init_plugin(void) {
	DECAF_printf("hello,world\n");
	DECAF_printf("%d\n", sizeof(plugin_term_cmds)/sizeof(*plugin_term_cmds));
	plugin_interface.mon_cmds = plugin_term_cmds;
	plugin_interface.plugin_cleanup = &plugin_cleanup;


	return (&plugin_interface);
}
