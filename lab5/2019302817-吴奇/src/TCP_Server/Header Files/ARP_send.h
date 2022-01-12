#include "Resource.h"

void load_arp_packet(u_int8_t* destination_ip, u_int16_t op_code);
/*
if the needer mac addr is not in arp_table, so request
*/
void arp_req_send(u_int8_t* destination_ip, u_int8_t* ethernet_dest_mac);
void arp_res_send(u_int8_t* destination_ip, u_int8_t* ethernet_dest_mac);
