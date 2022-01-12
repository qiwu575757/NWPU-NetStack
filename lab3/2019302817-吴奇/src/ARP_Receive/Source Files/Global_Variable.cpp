#include "Header_Include.h"
#include "Network_IPV4_recv.h"

u_int8_t local_mac[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
u_int8_t local_ip[4] = { 10, 10, 10, 10 };
u_int8_t gateway_ip[4] = { 10, 10, 11, 1 };
u_int8_t netmask[4] = { 255, 255, 248, 0 };
u_int8_t dns_server_ip[4] = { 211, 137, 130, 3 };
u_int8_t dhcp_server_ip[4] = { 111, 20, 62, 57 };
u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

pcap_t *handle;
int ethernet_upper_len;

//u_int8_t target_ip[4] = { 10, 71, 136, 1 };
using namespace std;
std::mutex recvlock1;//���廥�������ڶ� datalink �������Ļ������
std::mutex recvlock2;//���廥�������ڶ� datalink �������Ļ������
recvbuffer1 RECVBUFFER1;
recvbuffer2 RECVBUFFER2;