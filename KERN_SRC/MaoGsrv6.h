
#ifndef MAO_GSRV6_H
#define MAO_GSRV6_H

#include <linux/ipv6.h>

#define MAO_ROUTING_TYPE_GSRV6 33

struct mao_gsrv6_rh_header {
		u8		nh;
		u8		hdrlen;
		u8		rtype;
		u8		sl;
		u8		le;
		u8		cl:2,		// Mao: bitwise should be express in network byteorder (Little Endian).
				flags:6;	// Mao: for example: <linux/ipv6.h> line 231 & 232.
		u16		tag;
};

struct mao_gsrv6_srv6_gsid {
		u8		sid[16];
};

struct mao_gsrv6_compress_gsid {
	union{
		u32		csids[4];
		u8		csids8[16];
		struct {
			u8		csid3[4];
			u8		csid2[4];
			u8		csid1[4];
			u8		csid0[4];
		};
	};
};

struct mao_gsrv6_mpls_gsid {
	union{
		struct {
			u8		label3[4];
			u8		label2[4];
			u8		label1[4];
			u8		label0[4];
		};
		u32 labels[4];
	};
};

struct mao_gsrv6_ipv4_gsid {
		u32		type:4,
					resv:28;
		u8		src_ip[4];
		u8		dst_ip[4];
		u8		src_port[2];
		u8		dst_port[2];
};

struct mao_gsrv6_gsid {
	union {
		struct in6_addr ipv6;
		struct mao_gsrv6_srv6_gsid srv6;
		struct mao_gsrv6_compress_gsid compress;
		struct mao_gsrv6_mpls_gsid mpls;
		struct mao_gsrv6_ipv4_gsid ipv4;
	};
};


inline void mao_set_compress_gsid(struct mao_gsrv6_compress_gsid* compress_gsid, u32* csids, u8 amount)
{
	int i;
	memset(compress_gsid, 0, sizeof(*compress_gsid));
	for (i = 0; i < amount; i++)
	{
		compress_gsid->csids[4-amount + i] = csids[amount-1-i];
	}
}

inline void mao_set_compress_gsid_htonl(struct mao_gsrv6_compress_gsid* compress_gsid, u32* csids, u8 amount)
{
	int i;
	u32 csids_le[4] = {0};
	for (i =0; i < amount; i++) {
		csids_le[i] = m2l(csids + i);
	}
	mao_set_compress_gsid(compress_gsid, csids_le, amount);
}

#endif


























