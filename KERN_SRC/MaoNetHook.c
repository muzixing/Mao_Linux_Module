/*
===============================================================================
Driver Name		:		MaoNetHook
Author			:		JIANWEI MAO
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/

#include "MaoCommon.h"
#include "MaoNetHook.h"
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ipv6.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianwei Mao");



static struct kobject * mao_sysfs_root;
static char * statusBuff;



static ssize_t mao_sysfs_read(struct kobject * kobj, struct attribute * attr, char * buff)
{
	PINFO("%d", sprintf(buff, "%s", statusBuff));
	PINFO("READ, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, %ld",
			kobj->name, attr->name, buff, sizeof(buff), strlen(buff), PAGE_SIZE);

	return PAGE_SIZE - 1;
}

static ssize_t mao_sysfs_write(struct kobject * kobj, struct attribute * attr, const char * buff, size_t count)
{
	PINFO("WRITE, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, ActualCount:%ld, %ld",
			kobj->name, attr->name, buff, sizeof(buff), strlen(buff), count, PAGE_SIZE);

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
//	skb_network_header()
//	if ()
//	{
//		ipv6_hdr();
//	}


	int count;
	unsigned char * d = skb->data;
	if (skb->protocol == 0xDD86) // IPv6: 0x86DD
	{
		//unsigned short offset;
		//*((char*)(&offset)) = d[7]; *(((char*)(&offset)) + 1) = d[6];
		//offset &= 0x1FFF;

		/*
		count = sprintf(statusBuff,
				"IPv4\n"
				"Ver: %d\tIHL:%d\tDSCP:%d\tECN:%d\tTotalLen:%d\n"
				"PacketId:%d\tDF:%d\tMF:%d\tOffset:%d\n"
				"TTL:%d\tProtocol:%d\tChecksum:%d\n"
				"Src: %d.%d.%d.%d\tDst:%d.%d.%d.%d\n",
				d[0] >> 4, d[0] & 0x0F, d[1] >> 2, d[1] & 0x03, m2s(d+2),
				m2s(d+4), (d[6] >> 6) & 0x1, (d[6] >> 5) & 0x1, offset,//m2s((char*)&offset),
				d[8], d[9], m2s(d+10),
				d[12], d[13], d[14], d[15],
				d[16], d[17], d[18], d[19]);
		*/


		struct ipv6hdr* ip6_hdr = ipv6_hdr(skb);
		__u8 * sa = ip6_hdr->saddr.in6_u.u6_addr8;
		__u8 * da = ip6_hdr->daddr.in6_u.u6_addr8;

		count = sprintf(statusBuff,
				"IPv6\n"
				"Ver:%d\tDSCP:%02X\tFLowLabel:%02X, %02X, %02X\n"
				"PayloadLen:%d\tNextHeader:%d\tHopLimit:%d\n"
				"Src: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n"
				"Dst: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
				ip6_hdr->version, ip6_hdr->priority, ip6_hdr->flow_lbl[0], ip6_hdr->flow_lbl[1], ip6_hdr->flow_lbl[2],
				mao_ntohs_htons_val(ip6_hdr->payload_len), ip6_hdr->nexthdr, ip6_hdr->hop_limit,
				sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], sa[6], sa[7], sa[8], sa[9], sa[10], sa[11], sa[12], sa[13], sa[14], sa[15],
				da[0], da[1], da[2], da[3], da[4], da[5], da[6], da[7], da[8], da[9], da[10], da[11], da[12], da[13], da[14], da[15]);
	}


	//skb_cow_head(skb, tot_len + skb->mac_len);


	char * writeP = statusBuff + count;

	int i;
	for (i = 0; i < skb->len && i < 1000; i++)
	{
		sprintf(writeP+i*2, "%02X", skb->data[i]); // data - head = 16bytes, and they are all 0x00.
	}
	writeP[i*2] = '\n';
	writeP[i*2+1] = 0;

	sprintf(writeP + (i*2+1), "MaoHookGet, ifindex:%d, len:%d, ts:%d, mh:%d, ml:%d, nh:%d, th:%d, proto:%d; %010X, %010X, %010X, %010X",
			state->net->ifindex,
			skb->len,
			skb->truesize,
			skb->mac_header,
			skb->mac_len,
			skb->network_header,
			skb->transport_header,
			m2s((char*)(&(skb->protocol))),
			skb->head,
			skb->data,
			skb->tail,
			skb->end);

	return NF_ACCEPT;
}

static struct nf_hook_ops all_netns_hook_ops = {
		.hook = mao_nf_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = 3,
		.priority = NF_IP_PRI_FIRST,
};










static int __net_init netns_hook_init(struct net *net)
{

	PINFO("NETNS_HOOK_INIT: %d, %d, %d, %d, %d, HookRet:%d",
			net->ifindex,
			net->netns_ids.idr_base, net->netns_ids.idr_next,
			net->user_ns->owner, net->user_ns->group,
			nf_register_net_hook(net, &all_netns_hook_ops));

	return 0;
}

static void __net_exit netns_hook_exit(struct net *net)
{
	nf_unregister_net_hook(net, &all_netns_hook_ops);

	PINFO("NETNS_HOOK_EXIT", net->ifindex);
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

