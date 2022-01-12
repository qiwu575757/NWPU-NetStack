#include "Header_Include.h"

#define MAX_SIZE 2048
#define ETHERNET_IP 0X0800
#define ETHERNET_ARP 0X0806
#define ETHERNET_RARP 0X8035
#define ARP_HARDWARE 0X0001
#define ARP_REQUEST 0X0001
#define ARP_REPLY 0X0002
#define MAX_IP_PACKET_SIZE 1500
#define STATIC_STATE 0
#define DYNAMIC_STATE 1
#define LOGGING_STATE 2
#define MAX_DATA_SIZE 1000000
#define TOTAL_GROUPS 1
#define NUM_QUE 10
#define MSS 1000

//identify the host
#define	CLIENT	0
#define SERVER  1
//receive data statemachine
//#define CLOSED  0
//#define LISTEN  1
//#define SYNRECV  2
//#define ESTABLISHED  3
//#define CLOSEWAIT 4
//#define LASTACK 5

//send data statemachine
#define CLOSED  0
#define SYNSENT  1
#define ESTABLISHED  2
#define FINWAIT1  3
#define FINWAIT2 4
#define TIMEWAIT 5

//for tcp header flags
#define URG 0X20
#define ACK 0X10
#define PSH 0X08
#define RST 0X04
#define SYN 0X02
#define FIN 0X01

//receive queue for store the complete ip data from the datalink
#ifndef _recvbuffer1_h
#define _recvbuffer1_h
struct recvbuffer1 {
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1518];//定义接收缓冲区
	u_int16_t fragment[10];//定义每个分片的片偏移
	u_int16_t ethernet_type[NUM_QUE];
	int length[NUM_QUE];
	bool full;
	bool empty;
};
#endif // !recvbuffer1

#ifndef _recvbuffer2_h
#define _recvbuffer2_h
struct recvbuffer2 {//receive ip 
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1460];//定义接收缓冲区
	u_int16_t fragment[10];//定义每个分片的片偏移
	bool full;
	bool empty;
};
#endif // !recvbuffer2

#ifndef _recvbuffer3_h
#define _recvbuffer3_h
struct recvbuffer3 {//receive arp
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1518];//定义接收缓冲区
	bool full;
	bool empty;
};
#endif // !recvbuffer3

#ifndef _recvbuffer4_h
#define _recvbuffer4_h
struct recvbuffer4 {//receive udp datagram and add udp pseheader
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][16000];//定义接收缓冲区
	u_int32_t size_of_packet[NUM_QUE];
	bool full;
	bool empty;
};
#endif // !recvbuffer4

#ifndef _recvbuffer5_h
#define _recvbuffer5_h
struct recvbuffer5 {//receive tcp datagram and add udp pseheader
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1600];//tcp报文的数据部分一般需保证在ip层不会分片
	u_int32_t size_of_packet[NUM_QUE];
	bool full;
	bool empty;
};
#endif // !recvbuffer5

#ifndef _sendbuffer1_h
#define _sendbuffer1_h
//send buffer
struct sendbuffer1 {
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1600];
	u_int32_t ip_size_of_packet[NUM_QUE];
	u_int8_t destination_mac[NUM_QUE][6];
	u_int16_t type[NUM_QUE];
	bool full;
	bool empty;
};
#endif // !sendbuffer1

#ifndef _sendbuffer2_h
#define _sendbuffer2_h
//send buffer
struct sendbuffer2 {
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][16020];//include udp preheader, udp header, udp data
	u_int32_t size_of_packet[NUM_QUE];
	u_int8_t proto_type[NUM_QUE];
	bool full;
	bool empty;
};
#endif // !sendbuffer2

#ifndef _sendbuffer3_h//send udp datagram and include udp pseheader
#define _sendbuffer3_h
//send buffer
struct sendbuffer3 {
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][16000];//udp数据报数据部分最多为160000B
	u_int32_t size_of_packet[NUM_QUE];
	bool full;
	bool empty;
};
#endif // !sendbuffer3

#ifndef _arp_node_h
#define _arp_node_h
struct arp_node
{
	u_int8_t ip[4];
	u_int8_t mac[6];
	u_int8_t state;
	struct arp_node* next;
};
#endif // !arp_node

#ifndef _arp_table_header_h
#define _arp_table_header_h
struct arp_table_header
{
	arp_node* queue;
	arp_node* head;
	arp_node* tail;
};
#endif // !arp_table_header

#ifndef _arp_pkt_h
#define _arp_pkt_h
struct arp_pkt
{
	u_int16_t hardware_type;
	u_int16_t protocol_type;
	u_int8_t hardware_addr_length;
	u_int8_t protocol_addr_length;
	u_int16_t op_code;
	u_int8_t source_mac[6];
	u_int8_t source_ip[4];
	u_int8_t destination_mac[6]; //request the mac addr
	u_int8_t destination_ip[4];
};
#endif // !arp_pkt

#ifndef _ethernet_header_h
#define _ethernet_header_h
struct ethernet_header//工业以太网首部
{
	u_int8_t destination_mac[6];
	u_int8_t source_mac[6];
	u_int16_t ethernet_type;
};
#endif // !ethernet_header

#ifndef _ip_header_h
#define _ip_header_h
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
	u_int8_t source_ip[4];
	u_int8_t destination_ip[4];
	u_int8_t optional[40];//40 bytes is optional
};
#endif // !ip_header

//FOR ICMP
#ifndef _icmp_header_h
#define _icmp_header_h
struct icmp_header
{
	u_int8_t type_of_service;//类型
	u_int8_t op_code;//代码字段
	u_int16_t check_sum;
	u_int16_t id;//identification 
	u_int16_t num;	//序号
};
#endif // !_icmp_header_h

//FOR UDP
#ifndef _udp_header_h
#define _udp_header_h
struct udp_header
{
	u_int16_t src_port;
	u_int16_t dest_port;
	u_int16_t length;
	u_int16_t checknum;
};
#endif // !_udp_header_h

#ifndef _udp_pseheader_h
#define _udp_pseheader_h
struct udp_pseheader
{
	u_int8_t src_ip[4];
	u_int8_t dest_ip[4];
	u_int8_t reserve;
	u_int8_t protocol;
	u_int16_t length;
};
#endif // !_udp_pseheader_h

#ifndef _UDPSocket_h
#define _UDPSocket_h
struct UDPSocket
{
	u_int8_t local_ip[4];
	u_int8_t target_ip[4];
	u_int16_t local_port;
	u_int16_t target_port;
	u_int32_t sock_type;
};
#endif // !_UDPSocket_h

//FOR TCP 
#ifndef _tcp_header_h
#define _tcp_header_h
struct tcp_header
{
	u_int16_t src_port;
	u_int16_t dest_port;
	u_int32_t sequence;
	u_int32_t confirmnum;
	u_int8_t  header_length;//固定为常数
	u_int8_t  flags;
	u_int16_t window;
	u_int16_t checknum;
	u_int16_t urgent_pointer;
	u_int8_t options[4];//这里选项字段的含义是自定义的，主要用于双方协商mss大小
};
#endif // !_tcp_header_h

#ifndef _tcp_pseheader_h
#define _tcp_pseheader_h
struct tcp_pseheader
{
	u_int8_t src_ip[4];
	u_int8_t dest_ip[4];
	u_int8_t reserve;
	u_int8_t protocol;
	u_int16_t length;
};
#endif // !_tcp_pseheader_h

#ifndef _TCPSocket_h
#define _TCPSocket_h
struct TCPSocket
{
	u_int8_t local_ip[4];
	u_int8_t target_ip[4];
	u_int16_t local_port;
	u_int16_t target_port;
	u_int32_t sock_type;
};
#endif // !_TCPSocket_h

//tcp control block,定义tcp需要的全局变量
#ifndef _TCB_h
#define _TCB_h
struct TCB
{
	u_int32_t client_initial_seq;
	u_int32_t server_initial_seq;
	u_int16_t recv_window_size;
	u_int16_t recv_cache_size;
	u_int16_t send_window_size;
	u_int16_t send_cache_size;
	u_int16_t client_mss;
	u_int16_t server_mss;
	u_int16_t commuicate_mss;
};
#endif // !_TCB_h
