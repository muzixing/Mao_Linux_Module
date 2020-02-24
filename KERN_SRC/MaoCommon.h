
unsigned short mao_ntohs_htons(char * firstP)
{
	unsigned short ret;
	*((char*)(&ret)) = firstP[1];
	*(((char*)(&ret))+1) = firstP[0];
	return ret;
}

unsigned int mao_ntohl_htonl(char * firstP)
{
	unsigned int ret;
	*((char*)(&ret)) = firstP[3];
	*(((char*)(&ret))+1) = firstP[2];
	*(((char*)(&ret))+2) = firstP[1];
	*(((char*)(&ret))+3) = firstP[0];
	return ret;
}

#define m2s(firstP) mao_ntohs_htons(firstP)
#define m2l(firstP) mao_ntohl_htonl(firstP)
