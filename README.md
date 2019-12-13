# Honey Pot Bears Rootkit

## Project Description

[Course Project Description](https://www.securitee.org/teaching/cse331/projects/project1.html)

## Team Members

[Ilan Kleiman](https://github.com/shortland)

[Jenny (Mong Ting) Gao](https://github.com/chibiskye)

[Ibrahim Khan](https://github.com/khan-ibrahim)

[David Song](https://github.com/songdavid98)

## Work Distribution

1. Jenny - Hide specific files and directories from showing up when a user does "ls" and similar commands (you have to come up with a protocol that allows attackers to change these)

2. Ilan - Modify the /etc/passwd and /etc/shadow file to add a backdoor account while returning the original contents of the files (pre-attack) when a normal user requests to see the file

3. David - Hides specific processes from the process table when a user does a "ps"

4. Ibrahim - Implement framework for intercepting all syscalls. Give the ability to a malicious process to elevate its uid to 0 (root) upon demand.

## Resources Used
[Linux Kernel Module Programming Guide](https://www.tldp.org/LDP/lkmpg/2.6/html/x121.html)

[Updated LKMPG (see 4.15.2)](https://gitlab.com/bashrc2/LKMPG)

[Trail of Bits](https://blog.trailofbits.com/2019/01/17/how-to-write-a-rootkit-without-really-trying/)

[Goofkit](https://github.com/RITRedteam/goofkit/blob/master/goof.c)

[Diamorphine](https://github.com/m0nad/Diamorphine/blob/master/diamorphine.c)

## How to Use

Currently tested on Ubuntu server 18.04.3 (linuxkernel: 4.15.0-70-generic)

### Set Up Instructions

1. Clone the repo

2. Compile using `make` command

3. run `sudo insmod notarootkit.ko `. Optionally include additional arguments: `sudo insmod notarootkit.ko secretEscalationSig=331`.

### Attacker Usecases

#### Hide a file

Files with a secret prefix in the filename will be hidden from the user.

#### Hide a process

This will allow the attacker to run their executables without allowing the normal user to see the attacker's executables. The user will not be able to see the hidden processes with the ps command.

#### Insert backdoor and return fake passwd and shadow

This will create a user in the /etc/passwd & /etc/shadow file. The user will is not visible to anyone who opens the file.

#### Allow a process to escalate its privileges

The process should run kill, passing the secretEscalationSig (default=42, can be configured on insmod).

### Clean up

`sudo rmmod notarootkit` to remove

Note: See output by typing journalctl --since "5 minutes ago"

## Detailed Implementation Explanation

### Modular Syscall Interception

**Primary Developer**: Khan

A maximum number of injectable target syscalls defined in the macro numTargets.

4 arrays, each of length numTarget:

* syscall_indices: defines the syscall for each target
* toInject: where you can configure whether to inject a target or not
* original_syscallPtrs: where the original syscall ptr(from the sys_call_table) is stored.
* totallyReal_sycallPtrs: where you must store ptrs to your fake syscall functions

To add a target, follow existing examples/do the following:

1. [Lookup](https://syscalls.kernelgrok.com) the syscall you wish to intercept. Note tthe syscall name (eg. "sys_read") and the method signature.
2. Create your fake syscall. It must have the same signature as the original. If you want to call the actual syscall, retrieve the ptr from the original_syscallPtrs[], cast to typeof(syscall_index), then make the call. See example at the end of the totallyReal_read method.
3. Increase value of numTarget by 1. Your targetIndex is going to be numTarget - 1 (because arrays start with 0). ONLY edit your targetIndex in each of the following arrays.
4. Add the your target's syscall macro to your targetIndex of the syscall_indices array
5. Set injection to true (1) or false (0) in your targetIndex of the toInject array
6. Save the address to your fake syscall at the targetIndex of the totallyReal_syscallPtrs[]. As of now, do this in the loadMod() function.
7. That's all you have to do. the injectSyscalls and restoreSyscalls functions will take care of the rest based on your input in steps 3-6.

### Hide entries from ls

**Primary Developer:** Gao

When the user runs an 'ls' command, the kernel makes a series of syscalls starting from `execve` and eventually to `getdents`-- a function that retrieves metadata on the called directory. Our rootkit intercepts any calls to `getdents` and modifies the contents of the directory metadata passed to the original function to hide specific files by removing the file metadata from the directory metadata. The original `getdents` function is called at the very beginning of the modified function to populate the contents of the buffer used to hold the directory metadata. The rootkit searches each filename in the directory metadata for a secret prefix that determines that the file in question should be hidden. In our demo, the secret prefix is a hardcoded string "secret" and can easily be changed with a quick edit to the source code. None of the code in the original function is affected during this process.

### Hide entries from ps

**Primary Developer:** Song

Hiding processes is done very similarly to hiding entries. When the user runs a 'ps' command, the kernel makes a call to sys_getdents. Specifically, running the ps command calls getdents to the /proc folder, which contains a folder for every process that is running on the machine. The program intercepts this call, and looks at the metadata to see if any folder name matches the PID of the process that we are trying to hide, and removes that folder's metadata from the directory metadata. Additionally, this program can also hide processes via process name as well. Every process folder in /proc contains a file called cmdline, which solely contains the name of the process. The program looks into /proc/PID/cmdline for every process, checks if the name matches the name of the process that we are trying to hide, and removes that folder's metadata. Both the PID and the process name are macros that you have to directly edit in our rootkit in order to choose which processes you want to hide.

### Create backdoor account and return fake passwd and shadow 

**Primary Developer:** Kleiman

Whenever a file is opened, it sends a system call the the kernel. That system call being `sys_openat` - which takes as a parameter the filename of the file that was requested to open. In this rootkit, we first make backups of both the `/etc/passwd` & `/etc/shadow` files- which are stored as `/etc/secretpasswd` & `/etc/secretshadow`. Then we create the user `hax0r` in the real `/etc/passwd` & `/etc/shadow` files. Then we intercept all the `sys_openat` system calls. If the file requested to be opened is the `/etc/passwd` or `/etc/shadow`, then their parameter specifying the filename is overwritten with the backed-up version that does not yet have the secret user. Hence any read calls will not show the secret user until the rootkit module is removed. You can optionally uncomment a line in the cleaup function of the module which deletes the secret user when the module is removed - hence leaving the system without a trace of the user. The `/etc/secretpasswd` and `/etc/secretshadow` files are hidden with this rootkits other abilities. T

### Allow process to elevate its UID to 0 (root) on demand

**Primary Developer**: Khan

A process signals to the kernel module that it wishes to elevate its UID by calling 'kill' with a secret signal (default 42). The rootkit intercepts the kill syscall, detects use of the secret syscall, and changes the uid of the calling process to 0 (in the cred struct of the task struct of said process.)

The kill command was used for communication since it has a field for variable input, signal. Sig has standard values 1-31, but can take any int. This makes it easy to define/identify non standard values to use for communication.
