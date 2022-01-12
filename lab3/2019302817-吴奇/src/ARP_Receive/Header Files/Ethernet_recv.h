#include "Header_Include.h"
#include "Resource.h"

struct ethernet_header
{
	u_int8_t destination_mac[6];
	u_int8_t source_mac[6];
	u_int16_t ethernet_type;
};

//receive queue for store the complete ip data from the datalink
struct recvbuffer1 {
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1460];//定义接收缓冲区
	u_int16_t fragment[10];//定义每个分片的片偏移
	bool full;
	bool empty;
};


//generate crc table
void generate_crc32_table();
//calculate crc
u_int32_t calculate_crc(u_int8_t *buffer, int len);
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
int is_accept_ethernet_packet(u_int8_t *packet_content, int len);
void open_device();
void close_device();
void init_recvbuffer1();
DWORD WINAPI datalink_receive(LPVOID pM);//create datalink receive the data





