#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>
#define HAVE_REMOTE
#define WPCAP
#include<pcap.h>
#include<WinSock2.h>
#define NUM_QUE 100
#include <mutex>
#include<iostream>

using namespace std;
extern std::mutex mylock1;//���廥�������ڶ� datalink �������Ļ������

//receive queue for store the complete ip data from the datalink
struct datalink_ip_receivequeue {
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1460];//������ջ�����
	u_int16_t fragment[10];//����ÿ����Ƭ��Ƭƫ��
	bool full;
	bool empty;
};
extern datalink_ip_receivequeue DATALINK_IP_RECEIVEQUEUE;

DWORD WINAPI datalink_receive(LPVOID pM);//create datalink receive the data
void generate_crc32_table();//generate crc table
u_int32_t calculate_crc(u_int8_t *buffer, int len);//calculate crc
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
void init_datalink_ip_receivequeue();