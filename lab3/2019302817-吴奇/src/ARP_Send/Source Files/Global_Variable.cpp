#include "Header_Include.h"
#include "Network_IPV4_send.h"

u_int8_t local_mac[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
u_int8_t local_ip[4] = { 10, 10, 10, 4 };
u_int8_t gateway_ip[4] = { 10, 10, 11, 1 };
u_int8_t netmask[4] = { 255, 255, 248, 0 };
u_int8_t dns_server_ip[4] = { 211, 137, 130, 3 };
u_int8_t dhcp_server_ip[4] = { 111, 20, 62, 57 };
u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

pcap_t *handle;
u_int8_t target_ip[4] = { 10, 10, 10, 10 };

bool arprecv_flag = false;
using namespace std;
std::mutex sendlock1;
std::mutex sendlock2;
sendbuffer1 SENDBUFFER1;
sendbuffer2 SENDBUFFER2;