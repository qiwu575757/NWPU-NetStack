#include "Ethernet.h"
#include "Resource.h"
#include<mutex>
#include<iostream>
#define TOTAL_IP_GROUPS 5
using namespace std;
extern std::mutex mylock;

struct ip_header
{
	u_int8_t version_hdrlen;// default IP version: ipv4, header_length: 60bytes
	u_int8_t type_of_service;//service type
	u_int16_t total_length;//total length
	u_int16_t id;			//identification
	u_int16_t fragment_offset;//packet maybe need to be fraged. 
	u_int8_t time_to_live; 
	u_int8_t upper_protocol_type;
	u_int16_t check_sum;
	struct in_addr source_ip; //this is a structure equval to u_int32_t
	struct in_addr destination_ip;
	u_int8_t optional[40];//40 bytes is optional
};

//read from the file and send ip packet call ethernet function to make a complete packet
DWORD WINAPI read_from_file(LPVOID pM);
DWORD WINAPI ip_send(LPVOID pM);//read from the buffer and send it to datalink
void init_sendbuffer();
u_int16_t calculate_check_sum(ip_header *ip_hdr, int len);
void load_ip_header(u_int8_t *ip_buffer);
void load_ip_data(u_int8_t* ip_buffer, FILE* fp, int len);

