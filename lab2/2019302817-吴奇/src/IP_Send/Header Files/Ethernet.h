#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<time.h>

#define HAVE_REMOTE
#define WPCAP
#include<pcap.h>
#include<WinSock2.h>

#pragma warning(disable:4996)

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
void load_ethernet_header(u_int8_t *buffer);
int load_ethernet_data(u_int8_t *buffer, u_int8_t *ip_buffer, int len);

int ethernet_send_packet(u_int8_t *buffer, pcap_t *handle);
void datalink_send(u_int8_t* ip_buffer, u_int32_t ip_size_of_packet);

