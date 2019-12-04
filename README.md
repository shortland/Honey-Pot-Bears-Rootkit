# Honey Pot Bears Rootkit

## Project Description

[CSE 331 Course Project Description](https://www.securitee.org/teaching/cse331/projects/project1.html)

## Team Members

[Ilan Kleiman](https://github.com/shortland)

[Jenny (Mong Ting) Gao](https://github.com/chibiskye)

[Ibrahim Khan](https://github.com/khan-ibrahim)

[David Song](https://github.com/songdavid98)

## Work Distribution

1. Jenny - Hide specific files and directories from showing up when a user does "ls" and similar commands (you have to come up with a protocol that allows attackers to change these)

2. Ilan - Modify the /etc/passwd and /etc/shadow file to add a backdoor account while returning the original contents of the files (pre-attack) when a normal user requests to see the file

3. David - Hides specific processes from the process table when a user does a "ps"

4. Ibrahim - Give the ability to a malicious process to elevate its uid to 0 (root) upon demand (again this involves coming up with a protocol for doing that)

## Resources Used
[Linux Kernel Module Programming Guide](https://www.tldp.org/LDP/lkmpg/2.6/html/x121.html)

[Updated LKMPG (see 4.15.2)](https://gitlab.com/bashrc2/LKMPG)

[Trail of Bits](https://blog.trailofbits.com/2019/01/17/how-to-write-a-rootkit-without-really-trying/)

[Goofkit](https://github.com/RITRedteam/goofkit/blob/master/goof.c)

[Diamorphine](https://github.com/m0nad/Diamorphine/blob/master/diamorphine.c)

## Notes

Currently tested on Ubuntu server 18.04.3 (shouldn't make a difference on desktop) & linuxkernel: 14.15.0-70-generic

See output by typing journalctl --since "5 minutes ago"

Read syscall currently successfully intercepted, replaced, and restored. Fills log fast - insmod and rmmod quickly.

### Modular Configurability Explained:

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


