#include "Ethernet.h"

//loading buffer
void load_ethernet_header(u_int8_t* destination_mac, u_int16_t ethernet_type);
int load_ethernet_data(u_int8_t* buffer, u_int8_t* upper_buffer, int len);
int ethernet_send_packet(u_int8_t* upper_buffer, u_int8_t* destination_mac, u_int16_t ethernet_type, u_int32_t ip_size_of_packet);

DWORD WINAPI datalink_send(LPVOID pM);
