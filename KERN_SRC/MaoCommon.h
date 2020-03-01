
inline unsigned short mao_ntohs_htons(char * firstP)
{
	unsigned short ret;
	*((char*)(&ret)) = firstP[1];
	*(((char*)(&ret))+1) = firstP[0];
	return ret;
}

inline unsigned int mao_ntohl_htonl(char * firstP)
{
	//no use
	unsigned int ret;
	*((char*)(&ret)) = firstP[3];
	*(((char*)(&ret))+1) = firstP[2];
	*(((char*)(&ret))+2) = firstP[1];
	*(((char*)(&ret))+3) = firstP[0];
	return ret;
}

inline unsigned short mao_ntohs_htons_val(unsigned short val)
{
	return mao_ntohs_htons((char*)(&val));
}

#define m2s(firstP) mao_ntohs_htons(firstP)
#define m2l(firstP) mao_ntohl_htonl(firstP)
