/*
===============================================================================
Driver Name		:		MaoNetHook
Author			:		JIANWEI MAO
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/

#include "MaoNetHook.h"
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianwei Mao");



static struct kobject * mao_sysfs_root;
static char * statusBuff;



static ssize_t mao_sysfs_read(struct kobject * kobj, struct attribute * attr, char * buff)
{
//	int i;
//	for (i = 0; i<PAGE_SIZE; i++)
//	{
//		buff[i] = '5'+(i%10);
//	}
	memcpy(buff, statusBuff, PAGE_SIZE);

	PINFO("READ, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, %ld", kobj->name, attr->name, buff, sizeof(buff), strlen(buff), PAGE_SIZE);

	return PAGE_SIZE - 1;
}

static ssize_t mao_sysfs_write(struct kobject * kobj, struct attribute * attr, const char * buff, size_t count)
{
	PINFO("WRITE, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, ActualCount:%ld, %ld", kobj->name, attr->name, buff, sizeof(buff), strlen(buff), count, PAGE_SIZE);

	memcpy(statusBuff, buff, count);

	PINFO("WRITE2, %ld, %ld, %ld, %d, %d, %d",
			ksize(buff), count, strlen(buff), buff[count-1], buff[count], buff[count+1]);

	return count;
}

static struct attribute mao_sysfs_default_attr = {
		.name = "status",
		.mode = 0666
};

static struct sysfs_ops mao_sysfs_func = {
		.show = mao_sysfs_read,
		.store = mao_sysfs_write
};

static struct kobj_type mao_sysfs_type = {
		.sysfs_ops = &mao_sysfs_func
};






static unsigned int mao_nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	char packet_buf[PAGE_SIZE];
	memset(packet_buf, 0, PAGE_SIZE);

	int i;
	for (i = 0; i < skb->len; i++)
	{
		sprintf(statusBuff+i*2, "%02X", skb->head[i]);
	}
	statusBuff[i*2] = '\n';
	statusBuff[i*2+1] = 0;

	sprintf(packet_buf, "MaoHookGet, netns:%d, len:%d, ts:%d, mh:%d, ml:%d, nh:%d, th:%d; %X, %X, %X, %X",
			state->net->ifindex,
			skb->len,
			skb->truesize,
			skb->mac_header,
			skb->mac_len,
			skb->network_header,
			skb->transport_header,
			skb->head,
			skb->data,
			skb->end,
			skb->tail);

	strcat(statusBuff, packet_buf);

	return NF_ACCEPT;
}

static struct nf_hook_ops all_netns_hook_ops = {
		.hook = mao_nf_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = 3,
		.priority = NF_IP_PRI_FIRST,
};










static int __net_init netns_hook_init(struct net *net)
{

	PINFO("NETNS_HOOK_INIT: %d, HookRet:%d", net->ifindex, nf_register_net_hook(net, &all_netns_hook_ops));

	return 0;
}

static void __net_exit netns_hook_exit(struct net *net)
{
	nf_unregister_net_hook(net, &all_netns_hook_ops);

	PINFO("NETNS_HOOK_EXIT: %d", net->ifindex);
}

static struct pernet_operations all_netns_ops = {
		.init = netns_hook_init,
		.exit = netns_hook_exit,
};










static int __init MaoNetHook_init(void)
{
	/* TODO Auto-generated Function Stub */

	PINFO("INIT");

	statusBuff = kzalloc(PAGE_SIZE, GFP_KERNEL);

	mao_sysfs_root = kobject_create_and_add("mao", NULL);
	mao_sysfs_root->ktype = &mao_sysfs_type;

	PINFO("%d, %d",
			sysfs_create_file(mao_sysfs_root, &mao_sysfs_default_attr),
			register_pernet_subsys(&all_netns_ops));


	return 0;
}

static void __exit MaoNetHook_exit(void)
{

	unregister_pernet_subsys(&all_netns_ops);

	sysfs_remove_file(mao_sysfs_root, &mao_sysfs_default_attr);

	kzfree(statusBuff);

	kobject_del(mao_sysfs_root);

	PINFO("EXIT");

}


//MODULE_LICENSE("Mao Private.");
//MODULE_AUTHOR("Jianwei Mao");
MODULE_DESCRIPTION("Mao linux module architecture.");
MODULE_VERSION("Mao v0.1");

MODULE_FIRMWARE("I need firmware1: qingdao");
MODULE_FIRMWARE("I need firmware2: beijing");

MODULE_ALIAS("Mao Alias.");
MODULE_SOFTDEP("Mao deps");

module_init(MaoNetHook_init);
module_exit(MaoNetHook_exit);

