#include "Ethernet.h"
#define MAX_DATA_SIZE 1000000
#define TOTAL_IP_GROUPS 5
extern std::mutex mylock2;////定义互斥锁用于对 ip 缓冲区的互斥访问

struct ip_header
{
	u_int8_t version_hdrlen;// default IP version: ipv4, header_length: 60bytes
	u_int8_t type_of_service;//service type
	u_int16_t total_length;//total length
	u_int16_t id;			//identification
	u_int16_t fragment_offset;//packet maybe need to be fraged, include the flags and fragment
	u_int8_t time_to_live;
	u_int8_t upper_protocol_type;
	u_int16_t check_sum;
	struct in_addr source_ip; //this is a structure equval to u_int32_t
	struct in_addr destination_ip;
	u_int8_t optional[40];//40 bytes is optional
};

//receive the commplete ip data and write it to a file
struct ip_receivebuffer {
	int head;
	int tail;
	u_int8_t pool[10][MAX_DATA_SIZE];//定义接收缓冲区
	int total_len[10];//定义数据报总长度
	bool full;
	bool empty;
};
extern ip_receivebuffer IP_RECEIVEBUFFER;

DWORD WINAPI ipv4_receive(LPVOID pM);
DWORD WINAPI ipv4_writetofile(LPVOID pM);
u_int16_t calculate_check_sum(ip_header *ip_hdr, int len);
void init_ip_receivebuffer();
int fragment_reassemble();
void swap_receivepool(int a, int b);
void update_thebuffer();