#include<stdio.h>
#include<stdlib.h>
#define HAVE_REMOTE
#include<pcap.h>
#include<WinSock2.h>
#include <mutex>
#include<iostream>

using namespace std;
#pragma warning(disable:4996)
#define NUM_QUE 100

//ethernet protocol header format
struct ethernet_header
{
	u_int8_t ether_dhost[6];//destination mac
	u_int8_t ether_shost[6];//src mac
	u_int16_t ether_type;
};
int Header_Size = sizeof(ethernet_header);//定义数据帧头 size
int adapter_id = 1;//定义接受方网络端口
u_int8_t accept_dest_mac[2][6] = { { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 }, { 0x00, 0x09, 0x73, 0x07, 0x74, 0x73 } };
u_int8_t accept_source_mac[2][6] = { { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 }, { 0x00, 0x09, 0x73, 0x07, 0x74, 0x73 } };
u_int32_t crc32_table[256];//crc 检验表
bool end_flag = false;//结束标志
std::mutex mylock;//定义互斥锁用于对缓冲区的互斥访问

struct recv_buffer {
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1500];//定义接收缓冲区
	bool full;
	bool empty;
}RECV_BUFFER;

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void init_recvbuffer();
void generate_crc32_table();
DWORD WINAPI receive(LPVOID pM);
DWORD WINAPI write_to_file(LPVOID pM);
u_int32_t calculate_crc(u_int8_t* buffer, int len);

//init the recv buffer
void init_recvbuffer()
{
	RECV_BUFFER.head = 0;
	RECV_BUFFER.tail = 0;
	RECV_BUFFER.full = false;
	RECV_BUFFER.empty = true;
}

//generate the crc32 table
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

//ethernet protocol analysis and receive the ethernet into the recvive buffer
void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	u_short ethernet_type;
	struct ethernet_header* ethernet_protocol;
	u_char* mac_string;
	static int packet_number = 1;
	ethernet_protocol = (struct ethernet_header*)packet_content;
	int len = packet_header->len;
	int i, j;

	////check the mac address
	////if the packet is sended to my pc or broadcast
	int flag = 2;
	for (i = 0; i < 2; i++)
	{
		flag = 2;
		for (j = 0; j < 6; j++)
		{
			if (ethernet_protocol->ether_dhost[j] == accept_dest_mac[i][j])
				continue;
			else
			{
				flag = i;
				break;
			}
		}
		if (flag != 2)continue;
		else
			break;
	}
	if (flag != 2)
	{
		return;
	}
	if (i == 0)
	{
		printf("It's broadcasted.\n");
	}
	// if the source is acceptable
	for (i = 0; i < 2; i++)
	{
		flag = 1;
		for (j = 0; j < 6; j++)
		{
			if (ethernet_protocol->ether_shost[j] == accept_source_mac[i][j])
				continue;
			else
			{
				flag = 0;
				break;
			}
		}
		if (flag)
			break;
	}
	if (flag == 0)	return;

	//see if the data is changed or not
	u_int32_t crc = calculate_crc((u_int8_t*)(packet_content + sizeof(ethernet_header)), len - 4 - sizeof(ethernet_header));
	if (crc != *((u_int32_t*)(packet_content + len - 4)))
	{
		printf("The data has been changed.\n");
		return;
	}
	//打印相关信息，此工作可以放在接收端也可以交给上层协议时进行
	printf("----------------------------\n");
	printf("capture %d packet\n", packet_number);
	printf("capture time: %d\n", packet_header->ts.tv_sec);
	printf("packet length: %d\n", packet_header->len);
	printf("-----Ethernet protocol-------\n");

	ethernet_type = ethernet_protocol->ether_type;
	printf("Ethernet type: %04x\n", ethernet_type);
	switch (ethernet_type)
	{
		case 0x0800:
			printf("Upper layer protocol: IPV4\n");
			break;
		case 0x0806:
			printf("Upper layer protocol: ARP\n");
			break;
		case 0x8035:
			printf("Upper layer protocol: RARP\n");
			break;
		case 0x814c:
			printf("Upper layer protocol: SNMP\n");
			break;
		case 0x8137:
			printf("Upper layer protocol: IPX\n");
			break;
		case 0x86dd:
			printf("Upper layer protocol: IPV6\n");
			break;
		case 0x880b:
			printf("Upper layer protocol: PPP\n");
			break;
		default:
			break;
	}
	mac_string = ethernet_protocol->ether_shost;
	printf("MAC source address: %02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3),
		*(mac_string + 4), *(mac_string + 5));
	mac_string = ethernet_protocol->ether_dhost;
	printf("MAC destination address: %02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2),
		*(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

	//show the data for debug;
	for (u_int8_t* p = (u_int8_t*)(packet_content + sizeof(ethernet_header)); p != (u_int8_t*)(packet_content + packet_header->len - 4); p++)
	{
		printf("%c", *p);
	}
	printf("\n");
	printf("----------------------\n");


	// write the received data into the file, analog upper layer protocol
	mylock.lock();//加锁实现互斥访问
	int k = 0;
	if (RECV_BUFFER.full == false)
	{
		for (u_int8_t* p = (u_int8_t*)(packet_content + sizeof(ethernet_header)); p != (u_int8_t*)(packet_content + packet_header->len - 4); p++)
		{
			RECV_BUFFER.pool[RECV_BUFFER.head][k++] = *p;
		}
		RECV_BUFFER.head = (RECV_BUFFER.head + 1) % NUM_QUE;
		RECV_BUFFER.empty = false;
	}
	if (RECV_BUFFER.head == RECV_BUFFER.tail)
		RECV_BUFFER.full = true;
	if (k < 1496)
		end_flag = true;
	mylock.unlock();

	packet_number++;
}

DWORD WINAPI receive(LPVOID pM)
{
	pcap_if_t* all_adapters;
	pcap_if_t* adapter;
	pcap_t* adapter_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	int id = 1;

	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &all_adapters, error_buffer) == -1)
	{
		fprintf(stderr, "Error in findalldevs_ex function: %s\n", error_buffer);
		return -1;
	}
	if (all_adapters == NULL)
	{
		printf("\nNo adapters found! Make sure WinPcap is installed!!!\n");
		return 0;
	}

	for (adapter = all_adapters; adapter != NULL; adapter = adapter->next) id++;
	//对本机网络端口环境进行检查
	if (adapter_id < 1 || adapter_id > id - 1)
	{
		printf("\n Adapter id out of range.\n");
		pcap_freealldevs(all_adapters);
		return -1;
	}

	adapter = all_adapters;
	for (id = 1; id < adapter_id; id++)
	{
		adapter = adapter->next;
	}
	//获得设备的 handle
	adapter_handle = pcap_open(adapter->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 5, NULL, error_buffer);
	if (adapter_handle == NULL)
	{
		fprintf(stderr, "\n Unable to open adapter: %s\n", adapter->name);
		pcap_freealldevs(all_adapters);
		return -1;
	}

	//不断的循环接收收到的分组
	pcap_loop(adapter_handle, NULL, ethernet_protocol_packet_callback, NULL);
	pcap_freealldevs(all_adapters);
}

DWORD WINAPI write_to_file(LPVOID pM)
{
	FILE* recvfile = fopen("recv_data.txt", "w");
	int sizeofbufffer;
	if (recvfile == NULL) {
		printf("opened error\n");
		system("pause");
		exit(1);
	}

	//若数据帧还未接收完或者接收缓冲区还有数据写入文件，需要继续写入
	int i = 0;
	while (end_flag == false || RECV_BUFFER.empty == false)
	{
		mylock.lock();
		if (RECV_BUFFER.empty == false)
		{
			printf("rececive ethnet is %d\n", ++i);
			fwrite(RECV_BUFFER.pool[RECV_BUFFER.tail], 1, sizeof(RECV_BUFFER.pool[RECV_BUFFER.tail]), recvfile);
			RECV_BUFFER.tail = (RECV_BUFFER.tail + 1) % NUM_QUE;
			RECV_BUFFER.full = false;
		}
		if (RECV_BUFFER.head == RECV_BUFFER.tail)
		{
			RECV_BUFFER.empty = true;
		}
		mylock.unlock();
	}
	fclose(recvfile);
	printf("-------------------End------------------\n");
	system("pause");
	exit(1);
}

int main()
{
	generate_crc32_table();
	init_recvbuffer();
	CreateThread(NULL, 0, receive, NULL, 0, NULL);
	CreateThread(NULL, 0, write_to_file, NULL, 0, NULL);

	while (1);
}