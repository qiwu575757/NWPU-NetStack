#include "Header_Include.h"

int is_accept_arp_packet(struct arp_pkt* arp_packet);
u_int8_t* network_arp_recv(u_int8_t* arp_buffer);
u_int8_t* arp_res_recv(u_int8_t* destination_ip);
void arp_recv();