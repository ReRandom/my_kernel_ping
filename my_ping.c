#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/netdevice.h>

MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Roman Ponomarenko <r.e.p@yandex.ru>");

#define PROC_FILE_NAME "my_ping"
#define MY_MODULE_NAME "my_ping"

ssize_t write_proc(struct file *filp, const char __user *buffer,
		size_t size, loff_t *offset);

static struct proc_dir_entry *proc_file;
static const struct file_operations proc_fops = {
.owner = THIS_MODULE,
.write = write_proc,
};

ssize_t write_proc(struct file *filp, const char __user *buffer,
		size_t size, loff_t *offset)
{
	char* kbuffer;
	__be32 dest_addr;
	__be32 source_addr;
	struct icmphdr icmp;
	__wsum csum;
	struct iphdr ip;
	struct ethhdr eth;
	struct sk_buff *skb;
	int ret = 0;

	source_addr = in_aton("192.168.56.102");

	kbuffer = (char*)kmalloc(size+1, GFP_KERNEL);
	copy_from_user(kbuffer, buffer, size);
	if (kbuffer[size-1] != '\0')
		kbuffer[size] = '\0';
	pr_info("[%s] write %s\n", MY_MODULE_NAME, kbuffer);

	dest_addr = in_aton(kbuffer);

//	pr_info("[%s] dst:%pI4 src:%pI4\n", MY_MODULE_NAME, dest_addr,
//			source_addr);

	icmp.type = ICMP_ECHO;
	icmp.code = 0;
	icmp.un.echo.id = 1234;
	icmp.un.echo.sequence = 1;
	icmp.checksum = 0;
	csum = csum_partial((char*)&icmp, sizeof(struct icmphdr), 0);
	icmp.checksum = csum_fold(csum);

	ip.version = 4;
	ip.ihl = 5;
	ip.tos = 0;
	ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip.id = 0;
	ip.frag_off = 0;
	ip.ttl = IPDEFTTL;
	ip.protocol = 1;
	ip.check = 0;
	ip.saddr = source_addr;
	ip.daddr = dest_addr;
	ip.check = ip_fast_csum((const void*)&ip, ip.ihl);

	memset(&eth, 0, sizeof(eth));
	eth.h_dest[0] = 0x0a;
	eth.h_dest[2] = 0x27;
	eth.h_source[0] = 0x08;
	eth.h_source[2] = 0x27;
	eth.h_source[3] = 0xcc;
	eth.h_source[4] = 0x55;
	eth.h_source[5] = 0xa7;
	eth.h_proto = htons(ETH_P_IP);

//	pr_info("[%s] dst:%pM src:%pM\n", MY_MODULE_NAME, eth.h_dest,
//			eth.h_source);

	skb = alloc_skb(sizeof(eth)+sizeof(ip)+sizeof(icmp), GFP_KERNEL);
	skb_reserve(skb, sizeof(eth)+sizeof(ip)+sizeof(icmp));
	skb_push(skb, sizeof(icmp));
	memcpy(skb->data, &icmp, sizeof(icmp));
	skb_push(skb, sizeof(ip));
	memcpy(skb->data, &ip, sizeof(ip));
	skb->network_header = skb->data - skb->head;
	skb_push(skb, sizeof(eth));
	memcpy(skb->data, &eth, sizeof(eth));
	skb->mac_header = skb->data - skb->head;
	skb->transport_header = 0;

	skb->dev = dev_get_by_name(&init_net, "enp0s3");
	if (skb->dev == NULL) {
		pr_err("[%s] dev == NULL\n", MY_MODULE_NAME);
		return size;
	}

	ret = dev_queue_xmit(skb);
	pr_info("[%s] xmit return %d\n", MY_MODULE_NAME, ret);
//	ip_local_out(

	kfree(kbuffer);
	return size;
}

static int __init hello_init(void)
{
	proc_file = proc_create(PROC_FILE_NAME, 0666, NULL, &proc_fops);
	if (proc_file == NULL) {
		pr_err("[%s] can't create /proc/%s\n", MY_MODULE_NAME, PROC_FILE_NAME);
		return -ENOMEM;
	}
	pr_info("[%s] init\n", MY_MODULE_NAME);
	return 0;
}

static void __exit hello_exit(void)
{
	proc_remove(proc_file);
	pr_info("[%s] exit\n", MY_MODULE_NAME);
}

module_init(hello_init);
module_exit(hello_exit);
