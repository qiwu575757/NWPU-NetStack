#include "Header_Include.h"

//ethernet header
struct ethernet_header
{
	u_int8_t destination_mac[6];
	u_int8_t source_mac[6];
	u_int16_t ethernet_type;
};

//calculate CRC
void generate_crc32_table();
u_int32_t calculate_crc(u_int8_t *buffer, int len);

//loading buffer
void load_ethernet_header(u_int8_t *destination_mac, u_int16_t ethernet_type);
int load_ethernet_data(u_int8_t *buffer, u_int8_t *upper_buffer, int len);
int ethernet_send_packet(u_int8_t* upper_buffer, u_int8_t* destination_mac, u_int16_t ethernet_type, u_int32_t ip_size_of_packet);
int is_accept_ethernet_packet(struct ethernet_header *ethernet_hdr);
void open_device();
void close_device();
//void datalink_send(u_int8_t* ip_buffer, u_int32_t ip_size_of_packet, u_int8_t* destination_mac, int TYPE);
u_int8_t* datalink_recvarp();
DWORD WINAPI datalink_send(LPVOID pM);
void init_sendbuffer1();
void init_sendbuffer2();