#include "Ethernet_recv.h"

struct ip_header
{
	u_int8_t version_hdrlen;// default IP version: ipv4, header_length: 60bytes
	u_int8_t type_of_service;//
	u_int16_t total_length;//
	u_int16_t id;			//identification
	u_int16_t fragment_offset;//packet maybe need to be fraged. 
	u_int8_t time_to_live;
	u_int8_t upper_protocol_type;
	u_int16_t check_sum;
	u_int8_t source_ip[4]; //this is a structure equval to u_int32_t
	u_int8_t destination_ip[4];
	u_int8_t optional[40];//40 bytes is optional
};

//receive the commplete ip data and write it to a file
struct recvbuffer2 {
	int head;
	int tail;
	u_int8_t pool[10][MAX_DATA_SIZE];//定义接收缓冲区
	int total_len[10];//定义数据报总长度
	bool full;
	bool empty;
};

u_int16_t calculate_check_sum(ip_header *ip_hdr, int len);
//there is some bits that value is 0, so len as a parameter join the function
int is_accept_ip_packet(struct ip_header *ip_hdr);
DWORD WINAPI ipv4_receive(LPVOID pM);
DWORD WINAPI ipv4_writetofile(LPVOID pM);
void init_recvbuffer2();
int fragment_reassemble();
void swap_receivepool(int a, int b);
void update_thebuffer();