#include<stdio.h>
#include<stdlib.h>
#define HAVE_REMOTE
#include<pcap.h>
#include <mutex>
#include<iostream>

using namespace std;
//#include<global.h>//将定义的全局变量引入作用域
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma warning(disable:4996)

#define ETHERNET_IP 0x0800	// send data type
#define MAX_PACKAGE_SIZE 1514
#define NUM_QUE 10			// queue lenth

char filename[MAX_PACKAGE_SIZE] = "data.txt";//the send file name, simulate the data from the upper data
u_int32_t crc32_table[256];//store the crc keys
u_int8_t DestinationMac[6] = { 0x00, 0x09, 0x73, 0x07, 0x74, 0x73 };
u_int8_t SourceMac[6] = { 0x00, 0x09, 0x73, 0x07, 0x74, 0x73 };
bool end_flag = false;
int adapter_id = 1;//定义网络设备端口号

std::mutex mylock;

//ethernet header
struct ethernet_header
{
	u_int8_t dest_mac[6];
	u_int8_t src_mac[6];
	u_int16_t ethernet_type;
};

//send buffer
struct send_buffer {
	int head;
	int tail;
	u_int8_t pool [NUM_QUE][MAX_PACKAGE_SIZE];
	bool full;
	bool empty;
	int packet_size[NUM_QUE];
}SEND_BUFFER;

//void P(int* s);
//void V(int* s);
DWORD WINAPI read_from_file(LPVOID pM);
DWORD WINAPI send(LPVOID pM);
void init_sendbuffer();
void load_ethernet_header(u_int8_t* buffer);
int load_ethernet_data(u_int8_t* buffer, FILE* fp);
void generate_crc32_table();
u_int32_t calculate_crc(u_int8_t* buffer, int len);

//init the send buffer
void init_sendbuffer()
{
	SEND_BUFFER.head = 0;
	SEND_BUFFER.tail = 0;
	SEND_BUFFER.full = false;
	SEND_BUFFER.empty = true;
}

//generate table
void generate_crc32_table()
{
	int i, j;
	u_int32_t crc;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
}

//calculate crc keys
u_int32_t calculate_crc(u_int8_t* buffer, int len)
{
	int i, j;
	u_int32_t crc;
	crc = 0xffffffff;
	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
	}
	crc ^= 0xffffffff;
	return crc;
}

void load_ethernet_header(u_int8_t* buffer)
{
	struct ethernet_header* hdr = (struct ethernet_header*)buffer;
	hdr->dest_mac[0] = DestinationMac[0];//this is where you can define the mac address
	hdr->dest_mac[1] = DestinationMac[1];
	hdr->dest_mac[2] = DestinationMac[2];
	hdr->dest_mac[3] = DestinationMac[3];
	hdr->dest_mac[4] = DestinationMac[4];
	hdr->dest_mac[5] = DestinationMac[5];
	hdr->src_mac[0] = SourceMac[0];//source mac address
	hdr->src_mac[1] = SourceMac[1];
	hdr->src_mac[2] = SourceMac[2];
	hdr->src_mac[3] = SourceMac[3];
	hdr->src_mac[4] = SourceMac[4];
	hdr->src_mac[5] = SourceMac[5];
	hdr->ethernet_type = ETHERNET_IP;
}

int load_ethernet_data(u_int8_t* buffer, FILE* fp)
{
	int size_of_data = 0;
	char tmp[MAX_PACKAGE_SIZE];
	size_of_data = fread(tmp, 1, 1496, fp);
	printf("size of data is %d", size_of_data);
	if (size_of_data == 0)
		return sizeof(ethernet_header);
	if (size_of_data < 1496)
		end_flag = true;
	while (size_of_data < 46 && size_of_data > 0 ) {
		*(tmp + size_of_data) = 0;
		size_of_data++;
	}
	u_int32_t crc = calculate_crc((u_int8_t*)tmp, size_of_data);

	int i;
	for (i = 0; i < size_of_data; i++)
	{
		*(buffer + i) = tmp[i];
	}
	*(u_int32_t*)(buffer + i) = crc;
	return (sizeof(ethernet_header) + size_of_data + 4);
}

DWORD WINAPI read_from_file(LPVOID pM) {
	FILE* fp = fopen("send_data.txt", "r");
	int HeaderSize = sizeof(ethernet_header);//定义数据帧头 size
	int ethernet_index = 0, size_of_packet;
	if (fp == NULL) {
		printf("\nThe file is opened error.\n");
		system("pause");
		exit(1);
	}
	while ( end_flag == false ) {
		mylock.lock();//加锁实现互斥访问
		if (SEND_BUFFER.full == false)
		{
			size_of_packet = load_ethernet_data(SEND_BUFFER.pool[SEND_BUFFER.head] + HeaderSize, fp);
			load_ethernet_header(SEND_BUFFER.pool[SEND_BUFFER.head]);
			SEND_BUFFER.packet_size[SEND_BUFFER.head] = size_of_packet;
			SEND_BUFFER.head = (SEND_BUFFER.head + 1) % NUM_QUE;
			SEND_BUFFER.empty = false;
			printf("\n生成第%d个帧\n", ethernet_index);
			ethernet_index++;
		}
		if (SEND_BUFFER.head == SEND_BUFFER.tail)
			SEND_BUFFER.full = true;

		mylock.unlock();
	}
}

DWORD WINAPI send(LPVOID pM) {
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_t* adhandle;
	int i = 0, size_of_packet;
	char ErrBuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, ErrBuf) == -1) {
		printf("\nError in findalldevs_ex function: %s\n", ErrBuf);
		system("pause");
		exit(1);
	}
	for (d = alldevs; d != NULL; d = d->next) 
		i++;
	if (i == 0) {
		printf("\nNo interfaces found!Make sure WinPcap is installed.\n");
		pcap_freealldevs(alldevs);
		system("pause");
		exit(1);
	}
	//对本机网络端口环境进行检查
	if (adapter_id < 1 || adapter_id > i) {
		printf("\n Adapter id out of range.\n");
		pcap_freealldevs(alldevs);
		system("pause");
		exit(1);
	}
	for (d = alldevs, i = 0; i < adapter_id - 1; d = d->next, i++);
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, ErrBuf)) == NULL) {
		printf("\nUnable to open the adapter.%s is not supported by WinPcap.\n", d->name);
		//pcap_freealldevs(alldevs);
		system("pause");
		exit(1);
	}

	while ( end_flag == false || SEND_BUFFER.empty == false ) {
		//若文件信息还未读完或者发送缓冲区还有数据未发出，需要继续发送
		mylock.lock();
		if (SEND_BUFFER.empty == false)
		{
			size_of_packet = SEND_BUFFER.packet_size[SEND_BUFFER.tail];
			if (pcap_sendpacket(adhandle, (const u_char*)SEND_BUFFER.pool[SEND_BUFFER.tail], size_of_packet) != 0)
				printf("\n%d.Error sending the packet:%s\n", SEND_BUFFER.tail, pcap_geterr(adhandle));
			else
				printf("\nPacket %d has been sent.\n", SEND_BUFFER.tail);
			SEND_BUFFER.tail = (SEND_BUFFER.tail + 1) % NUM_QUE;
			SEND_BUFFER.full = false;
		}
		if (SEND_BUFFER.head == SEND_BUFFER.tail)
			SEND_BUFFER.empty = true;
		mylock.unlock();
	}

	pcap_freealldevs(alldevs);
	printf("\n数据帧已经发送完成\n");
	system("pause");
	exit(1);
}

int main()
{
	generate_crc32_table();
	CreateThread(NULL, 0, read_from_file, NULL, 0, NULL);//create thread to read data from file
	CreateThread(NULL, 0, send, NULL, 0, NULL);//create thread to send data ethnet
	while (1);

	system("pause");
	return 0;
}