#include "Ethernet.h"

extern u_int32_t crc32_table[256];
extern u_int8_t local_mac[6];
extern pcap_t* handle;
extern sendbuffer1 SENDBUFFER1;
extern sendbuffer2 SENDBUFFER2;
extern sendbuffer3 SENDBUFFER3;
extern recvbuffer1 RECVBUFFER1;
extern recvbuffer2 RECVBUFFER2;
extern recvbuffer3 RECVBUFFER3;
extern recvbuffer4 RECVBUFFER4;

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

u_int32_t calculate_crc(u_int8_t* buffer, int len)
{
	int i;
	u_int32_t crc;
	crc = 0xffffffff;
	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
	}
	crc ^= 0xffffffff;
	return crc;
}

int is_accept_ethernet_packet(u_int8_t* packet_content, int len)
{
	struct ethernet_header* ethernet_hdr = (struct ethernet_header*)packet_content;
	int i;
	int flag = 0;
	for (i = 0; i < 6; i++)
	{
		if (ethernet_hdr->destination_mac[i] != 0xff)break;
	}

	if (i == 6)
	{
		flag = 1;
		printf("It's broadcast packet.\n");
	}

	for (i = 0; i < 6; i++)
	{
		if (ethernet_hdr->destination_mac[i] != local_mac[i])break;
	}

	if (i == 6)
	{
		flag = 1;
		printf("It's sended to my pc.\n");
	}
	if (!flag)
		return 0;

	//generate_crc32_table();
	//crc match
	u_int32_t crc = calculate_crc((u_int8_t*)(packet_content + sizeof(ethernet_header)), len - 4 - sizeof(ethernet_header));
	if (crc != *((u_int32_t*)(packet_content + len - 4)))
	{
		printf("The data has changed.\n");
		return 0;
	}
	return 1;
}

void output_mac(u_int8_t mac[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (i)printf("-");
		printf("%02x", mac[i]);
	}
	printf("\n");
}

void open_device()
{
	generate_crc32_table();
	char* device;
	char error_buffer[PCAP_ERRBUF_SIZE];

	device = pcap_lookupdev(error_buffer);

	handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);
}

void close_device()
{
	pcap_close(handle);
}

void init_buffer()
{
	SENDBUFFER1.head = 0;
	SENDBUFFER1.tail = 0;
	SENDBUFFER1.full = false;
	SENDBUFFER1.empty = true;

	SENDBUFFER2.head = 0;
	SENDBUFFER2.tail = 0;
	SENDBUFFER2.full = false;
	SENDBUFFER2.empty = true;

	SENDBUFFER3.head = 0;
	SENDBUFFER3.tail = 0;
	SENDBUFFER3.full = false;
	SENDBUFFER3.empty = true;

	RECVBUFFER1.head = 0;
	RECVBUFFER1.tail = 0;
	RECVBUFFER1.full = false;
	RECVBUFFER1.empty = true;

	RECVBUFFER2.head = 0;
	RECVBUFFER2.tail = 0;
	RECVBUFFER2.full = false;
	RECVBUFFER2.empty = true;

	RECVBUFFER3.head = 0;
	RECVBUFFER3.tail = 0;
	RECVBUFFER3.full = false;
	RECVBUFFER3.empty = true;

	RECVBUFFER4.head = 0;
	RECVBUFFER4.tail = 0;
	RECVBUFFER4.full = false;
	RECVBUFFER4.empty = true;
}
