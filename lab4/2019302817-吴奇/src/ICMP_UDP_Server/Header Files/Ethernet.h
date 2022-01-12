#include "Resource.h"

//generate crc table
void generate_crc32_table();
//calculate crc
u_int32_t calculate_crc(u_int8_t* buffer, int len);

int is_accept_ethernet_packet(u_int8_t* packet_content, int len);
void open_device();
void close_device();
void output_mac(u_int8_t mac[6]);
void init_buffer();
