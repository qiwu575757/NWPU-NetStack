#include "Resource.h"

u_int8_t gateway_ip[4] = { 10, 10, 11, 1 };
u_int8_t netmask[4] = { 255, 255, 248, 0 };
u_int8_t dns_server_ip[4] = { 211, 137, 130, 3 };
u_int8_t dhcp_server_ip[4] = { 111, 20, 62, 57 };
u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
u_int8_t local_mac[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
u_int8_t local_ip[4] = { 10, 10, 10, 4 };
u_int16_t  local_port = 49153;
u_int16_t  server_port = 49154;
u_int8_t target_ip[4] = { 10, 10, 10, 10 };
u_int8_t server_ip[4] = { 10, 10, 10, 10 };//服务器端的本地ip地址和服务器ip地址是一样的吗

u_int32_t crc32_table[256];
pcap_t* handle;
int ethernet_upper_len;
bool arprecv_flag = false;
bool send_endflag = false;
bool recv_endflag = false;

//for icmp request and resonse
u_int8_t local_id[2] = {0x12, 0x34};//本机标识符
u_int8_t local_num[2] = { 0x00, 0x00 };//序列号字段，依次递增

using namespace std;
std::mutex sendlock1;//定义互斥锁用于对共享缓冲区的访问
std::mutex sendlock2;
std::mutex sendlock3;

std::mutex recvlock1;
std::mutex recvlock2;
std::mutex recvlock3;
std::mutex recvlock4;

sendbuffer1 SENDBUFFER1;
sendbuffer2 SENDBUFFER2;
sendbuffer3 SENDBUFFER3;
recvbuffer1 RECVBUFFER1;
recvbuffer2 RECVBUFFER2;
recvbuffer3 RECVBUFFER3;
recvbuffer4 RECVBUFFER4;
