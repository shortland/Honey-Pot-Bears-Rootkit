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

##Notes
Currently tested on Ubuntu server 18.04.3 (shouldn't make a difference on desktop) & linuxkernel: 14.15.0-70-generic

See output by typing journalctl --since "5 minutes ago"

Read syscall currently successfully intercepted, replaced, and restored. Fills log fast - insmod and rmmod quickly.


