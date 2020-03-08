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
#include "MaoGsrv6.h"

#include <linux/slab.h>
#include <net/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianwei Mao");


#define MAO_SYSFS_FILE_STATUS "status"
#define MAO_SYSFS_FILE_FLOW_SRC "flow_src"
#define MAO_SYSFS_FILE_FLOW_DST "flow_dst"
#define MAO_SYSFS_FILE_TUNNEL_SRC "tunnel_src"
#define MAO_SYSFS_FILE_TUNNEL_DST "tunnel_dst"




static struct kobject * mao_sysfs_root;
static char * statusBuff;
static struct in6_addr flow_src = {0x20, 0x01, 0,0,0,0,0,0,0,0,0,0,0,0,0, 0x01};
static struct in6_addr flow_dst = {0x20, 0x01, 0,0,0,0,0,0,0,0,0,0,0,0,0, 0x01};
static struct in6_addr tunnel_src = {0x20, 0x33, 0x08, 0x10, 0x03, 0,0,0,0,0,0,0,0,0,0, 0x33};
static struct in6_addr tunnel_dst = {0x20, 0x33, 0x08, 0x10, 0x06, 0,0,0,0,0,0,0,0,0,0, 0x66};



static ssize_t mao_sysfs_read(struct kobject * kobj, struct attribute * attr, char * buff)
{
	//PINFO("READ, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, %ld",
	//		kobj->name, attr->name, buff, sizeof(buff), strlen(buff), PAGE_SIZE);

	if (0 == strcmp(attr->name, MAO_SYSFS_FILE_STATUS)) {
		return sprintf(buff, "%s", statusBuff); // PAGE_SIZE - 1;

	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_FLOW_SRC)) {
		return 0;
	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_FLOW_DST)) {
		return 0;
	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_TUNNEL_SRC)) {
		return 0;
	} else if (0 == strcmp(attr->name, MAO_SYSFS_FILE_TUNNEL_DST)) {
		return 0;
	} else {
		return 0;
	}
}

static ssize_t mao_sysfs_write(struct kobject * kobj, struct attribute * attr, const char * buff, size_t count)
{
	//PINFO("WRITE, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, ActualCount:%ld, %ld",
	//		kobj->name, attr->name, buff, sizeof(buff), strlen(buff), count, PAGE_SIZE);

	memcpy(statusBuff, buff, count);

	//PINFO("WRITE2, %ld, %ld, %ld, %d, %d, %d",
	//		ksize(buff), count, strlen(buff), buff[count-1], buff[count], buff[count+1]);

	return count;
}


static struct attribute mao_sysfs_attrs[] = {
		{.name = MAO_SYSFS_FILE_STATUS, .mode = 0666},
		{.name = MAO_SYSFS_FILE_FLOW_SRC, .mode = 0666},
		{.name = MAO_SYSFS_FILE_FLOW_DST, .mode = 0666},
		{.name = MAO_SYSFS_FILE_TUNNEL_SRC, .mode = 0666},
		{.name = MAO_SYSFS_FILE_TUNNEL_DST, .mode = 0666},
};


static struct sysfs_ops mao_sysfs_func = {
		.show = mao_sysfs_read,
		.store = mao_sysfs_write
};

static struct kobj_type mao_sysfs_type = {
		.sysfs_ops = &mao_sysfs_func
};


static void mao_register_sysfs_files(void)
{
	mao_sysfs_root = kobject_create_and_add("mao", NULL);
	mao_sysfs_root->ktype = &mao_sysfs_type;

	sysfs_create_file(mao_sysfs_root, mao_sysfs_attrs + 0);
	sysfs_create_file(mao_sysfs_root, mao_sysfs_attrs + 1);
	sysfs_create_file(mao_sysfs_root, mao_sysfs_attrs + 2);
	sysfs_create_file(mao_sysfs_root, mao_sysfs_attrs + 3);
	sysfs_create_file(mao_sysfs_root, mao_sysfs_attrs + 4);
}

static void mao_unregister_sysfs_files(void)
{
	sysfs_remove_file(mao_sysfs_root, mao_sysfs_attrs + 0);
	sysfs_remove_file(mao_sysfs_root, mao_sysfs_attrs + 1);
	sysfs_remove_file(mao_sysfs_root, mao_sysfs_attrs + 2);
	sysfs_remove_file(mao_sysfs_root, mao_sysfs_attrs + 3);
	sysfs_remove_file(mao_sysfs_root, mao_sysfs_attrs + 4);

	kobject_del(mao_sysfs_root);
}





static bool is_interest_flow(struct in6_addr * flow_addr_src, struct in6_addr * flow_addr_dst) //
{
	//PINFO("SIZE: %d, %d", sizeof(*flow_addr_src), sizeof(*flow_addr_dst));
	//PINFO("\n"
	//		"F_SRC: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n"
	//		"F_DST: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n"
	//		"FS_SRC: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n"
	//		"FS_DST: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
	//		flow_addr_src->s6_addr[0], flow_addr_src->s6_addr[1], flow_addr_src->s6_addr[2], flow_addr_src->s6_addr[3], flow_addr_src->s6_addr[4], flow_addr_src->s6_addr[5], flow_addr_src->s6_addr[6], flow_addr_src->s6_addr[7], flow_addr_src->s6_addr[8], flow_addr_src->s6_addr[9], flow_addr_src->s6_addr[10], flow_addr_src->s6_addr[11], flow_addr_src->s6_addr[12], flow_addr_src->s6_addr[13], flow_addr_src->s6_addr[14], flow_addr_src->s6_addr[15],
	//		flow_addr_dst->s6_addr[0], flow_addr_dst->s6_addr[1], flow_addr_dst->s6_addr[2], flow_addr_dst->s6_addr[3], flow_addr_dst->s6_addr[4], flow_addr_dst->s6_addr[5], flow_addr_dst->s6_addr[6], flow_addr_dst->s6_addr[7], flow_addr_dst->s6_addr[8], flow_addr_dst->s6_addr[9], flow_addr_dst->s6_addr[10], flow_addr_dst->s6_addr[11], flow_addr_dst->s6_addr[12], flow_addr_dst->s6_addr[13], flow_addr_dst->s6_addr[14], flow_addr_dst->s6_addr[15],
	//		flow_src.s6_addr[0], flow_src.s6_addr[1], flow_src.s6_addr[2], flow_src.s6_addr[3], flow_src.s6_addr[4], flow_src.s6_addr[5], flow_src.s6_addr[6], flow_src.s6_addr[7], flow_src.s6_addr[8], flow_src.s6_addr[9], flow_src.s6_addr[10], flow_src.s6_addr[11], flow_src.s6_addr[12], flow_src.s6_addr[13], flow_src.s6_addr[14], flow_src.s6_addr[15],
	//		flow_dst.s6_addr[0], flow_dst.s6_addr[1], flow_dst.s6_addr[2], flow_dst.s6_addr[3], flow_dst.s6_addr[4], flow_dst.s6_addr[5], flow_dst.s6_addr[6], flow_dst.s6_addr[7], flow_dst.s6_addr[8], flow_dst.s6_addr[9], flow_dst.s6_addr[10], flow_dst.s6_addr[11], flow_dst.s6_addr[12], flow_dst.s6_addr[13], flow_dst.s6_addr[14], flow_dst.s6_addr[15]);

	return 0 == memcmp(flow_addr_src, &flow_src, sizeof(*flow_addr_src)) &&
			0 == memcmp(flow_addr_dst, &flow_dst, sizeof(*flow_addr_dst));
}

static unsigned int mao_nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	// encap G-SRv6

	struct ipv6hdr *outer_hdr, *inner_hdr;
	struct mao_gsrv6_rh_header *gsrv6_rh;
	struct mao_gsrv6_gsid *gsid_list;
	int cow_total_len;
	int err;


	/*** 0. catch inner ipv6 header ***/
	inner_hdr = ipv6_hdr(skb);
	if (is_interest_flow(&inner_hdr->saddr, &inner_hdr->daddr)) {

		/*** 1. extend skb ***/
		cow_total_len = sizeof(*outer_hdr)  + sizeof(*gsrv6_rh) + sizeof(*gsid_list)*7;
		err = skb_cow_head(skb, cow_total_len);
		if(unlikely(err))
			return NF_STOLEN; // means cow failure


		/*** 2. refresh layer pointer ***/
		skb_push(skb, cow_total_len);
		skb_reset_network_header(skb);
		skb_mac_header_rebuild(skb);

		outer_hdr = ipv6_hdr(skb);
		gsrv6_rh = (void *) outer_hdr + sizeof(*outer_hdr);
		gsid_list = (void *) gsrv6_rh + sizeof(*gsrv6_rh);


		/*** 3. prepare outer IPv6 header ***/

		// method 1 - ip6_flow_hdr(outer_hdr, 55, m2lv(0xA2703));
		// method 2 - ip6_flow_hdr(outer_hdr, inner_hdr->priority, m2lv(0xA2703));
		// method 2 - memcpy(outer_hdr->flow_lbl, inner_hdr->flow_lbl, 3);
		memcpy(outer_hdr, inner_hdr, 4); // method 3

		// Mao: should convert to host byteorder first, then calculate, finally convert to network byteorder.
		// Mao: if we add two network byteorder, we may hit overflow bug.
		outer_hdr->payload_len = m2sv(sizeof(*gsrv6_rh) + sizeof(*gsid_list)*7 + sizeof(*inner_hdr) + m2sv(inner_hdr->payload_len));
		outer_hdr->nexthdr = NEXTHDR_ROUTING;
		outer_hdr->hop_limit = inner_hdr->hop_limit;
		outer_hdr->saddr = tunnel_src;
		outer_hdr->daddr = tunnel_dst;


		/*** 4. prepare G-SRv6 routing header ***/
		memset(gsrv6_rh, 0, sizeof(*gsrv6_rh));
		gsrv6_rh->nh = NEXTHDR_IPV6;
		gsrv6_rh->hdrlen = sizeof(*gsid_list) * 7 / 8;
		gsrv6_rh->rtype = MAO_ROUTING_TYPE_GSRV6;
		gsrv6_rh->sl = 6;
		gsrv6_rh->le = 7;
		gsrv6_rh->flags = 22;
		gsrv6_rh->cl = 2;
		gsrv6_rh->tag = m2sv(0x0810);


		/*** 5. prepare G-SRv6 G-SID list ***/
		memset(gsid_list, 0, sizeof(*gsid_list)*7);
		u32 csids[4] = {0x7181, 0x1080, 0x5511, 0x522703};
		mao_set_compress_gsid_htonl((struct mao_gsrv6_compress_gsid*)(gsid_list), csids, 4);
		mao_set_compress_gsid_htonl((struct mao_gsrv6_compress_gsid*)(gsid_list+1), csids, 4);
		mao_set_compress_gsid_htonl((struct mao_gsrv6_compress_gsid*)(gsid_list+2), csids, 4);
		mao_set_compress_gsid_htonl((struct mao_gsrv6_compress_gsid*)(gsid_list+3), csids, 4);
		mao_set_compress_gsid_htonl((struct mao_gsrv6_compress_gsid*)(gsid_list+4), csids, 4);
		mao_set_compress_gsid_htonl((struct mao_gsrv6_compress_gsid*)(gsid_list+5), csids, 4);
		mao_set_compress_gsid_htonl((struct mao_gsrv6_compress_gsid*)(gsid_list+6), csids, 4);


		/*** X. others backup ***/
		// if hook doesn't specify IPv6(inner L3 is not IPv6), need to set control block(IP6CB).
		//if (skb->protocol != htons(ETH_P_IPV6))	memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));




		/*** debug: parse & show packet header ***/

		int count;
		//unsigned char * d = skb->data;
		//if (skb->protocol == 0xDD86) // IPv6: 0x86DD
		//{
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


			//struct mao_gsrv6_compress_gsid* csid_point = gsid_list;
			count = sprintf(statusBuff,
					"IPv6\n"
					"Ver:%d\tDSCP:%02X\tFLowLabel:%02X, %02X, %02X\n"
					"PayloadLen:%d\tNextHeader:%d\tHopLimit:%d\n"
					"Src: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n"
					"Dst: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n"
					"\n"
					"G-SRv6 Header\n"
					"NH:%02X\tHdrlen:%02X\tRT:%02X\tSL:%02X\n"
					"LE:%02X\tFlags:%02X\tCL:%02X\tTag:%04X\n"
					"",
					ip6_hdr->version, ip6_hdr->priority, ip6_hdr->flow_lbl[0], ip6_hdr->flow_lbl[1], ip6_hdr->flow_lbl[2],
					mao_ntohs_htons_val(ip6_hdr->payload_len), ip6_hdr->nexthdr, ip6_hdr->hop_limit,
					sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], sa[6], sa[7], sa[8], sa[9], sa[10], sa[11], sa[12], sa[13], sa[14], sa[15],
					da[0], da[1], da[2], da[3], da[4], da[5], da[6], da[7], da[8], da[9], da[10], da[11], da[12], da[13], da[14], da[15],

					gsrv6_rh->nh, gsrv6_rh->hdrlen, gsrv6_rh->rtype, gsrv6_rh->sl,
					gsrv6_rh->le, gsrv6_rh->flags, gsrv6_rh->cl, gsrv6_rh->tag);
		//}


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


	}

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
	PINFO("INIT");

	statusBuff = kzalloc(PAGE_SIZE, GFP_KERNEL);

	register_pernet_subsys(&all_netns_ops);

	mao_register_sysfs_files();

	return 0;
}

static void __exit MaoNetHook_exit(void)
{
	mao_unregister_sysfs_files();

	unregister_pernet_subsys(&all_netns_ops);

	kzfree(statusBuff);

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

