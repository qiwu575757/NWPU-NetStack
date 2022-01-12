#include "Ethernet.h"
#include "Resource.h"
#include"Network_IPV4_send.h"
#include"Network_ARP_recv.h"

u_int32_t crc32_table[256] = { 0 };
u_int32_t size_of_packet = 0;

u_int8_t buffer[MAX_SIZE];
extern pcap_t *handle;
extern u_int8_t local_mac[6];

extern std::mutex sendlock2;
extern sendbuffer2 SENDBUFFER2;

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

u_int32_t calculate_crc(u_int8_t *buffer, int len)
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


void load_ethernet_header(u_int8_t *destination_mac,u_int16_t ethernet_type)
{
	struct ethernet_header *hdr = (struct ethernet_header *)buffer;
	size_of_packet = 0;
	// add destination mac address
	hdr->destination_mac[0] = destination_mac[0];
	hdr->destination_mac[1] = destination_mac[1];
	hdr->destination_mac[2] = destination_mac[2];
	hdr->destination_mac[3] = destination_mac[3];
	hdr->destination_mac[4] = destination_mac[4];
	hdr->destination_mac[5] = destination_mac[5];

	//add source mac address
	hdr->source_mac[0] = local_mac[0];
	hdr->source_mac[1] = local_mac[1];
	hdr->source_mac[2] = local_mac[2];
	hdr->source_mac[3] = local_mac[3];
	hdr->source_mac[4] = local_mac[4];
	hdr->source_mac[5] = local_mac[5];

	// add source typy
	hdr->ethernet_type = htons(ethernet_type);

	// caculate the size of packet now
	size_of_packet += sizeof(ethernet_header);
}

int load_ethernet_data(u_int8_t *buffer, u_int8_t *upper_buffer, int len)
{
	if (len > 1500)
	{
		printf("IP buffer is too large. So we stop the procedure.");
		return -1;
	}

	int i;
	for (i = 0; i < len; i++)
	{
		*(buffer + i) = *(upper_buffer + i);
	}

	//add a serial 0 at the end
	while (len < 46)
	{
		*(buffer + len) = 0;
		len++;
	}
    
    //generate_crc32_table();
	u_int32_t crc = calculate_crc(buffer, len);

	*(u_int32_t *)(buffer + len) = crc;
	size_of_packet += len + 4;
	return 1;
}

int ethernet_send_packet(u_int8_t *upper_buffer,u_int8_t *destination_mac,u_int16_t ethernet_type, u_int32_t ip_size_of_packet)
{
	load_ethernet_header(destination_mac, ethernet_type);
	load_ethernet_data(buffer + sizeof(struct ethernet_header), upper_buffer, ip_size_of_packet);

	if (pcap_sendpacket(handle, (const u_char *)buffer, size_of_packet) != 0)
	{
		printf("Sending failed..\n");
		return -1;
	}
	else
	{
		printf("Sending Succeed..\n");
		return 1;
	}
}

void open_device()
{
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];

	device = pcap_lookupdev(error_buffer);
	handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);
	generate_crc32_table();
}

void close_device()
{
	pcap_close(handle);
}

//broadcast and local is acceptable
int is_accept_ethernet_packet(struct ethernet_header *ethernet_hdr)
{
	int i;
	for (i = 0; i < 6; i++)
	{
		if (ethernet_hdr->destination_mac[i] != 0xff)
			break;
	}
	if (i == 6)
	{
		printf("It's broadcast packet.\n");
		return 1;
	}

	for (i = 0; i < 6; i++)
	{
		if (ethernet_hdr->destination_mac[i] != local_mac[i])
			break;
	}

	if (i == 6)
	{
		printf("It's sended to my pc.\n");
		return 1;
	}
	return 0;
}

u_int8_t* datalink_recvarp()
{
	open_device();

	//wait for replying, get the destination mac
	struct pcap_pkthdr* pkt_hdr;
	u_int8_t* pkt_content;
	u_int8_t* destination_mac = NULL;
	while (pcap_next_ex(handle, &pkt_hdr, (const u_char**)&pkt_content) != 0)
	{
		//get the ethernet header
		struct ethernet_header* ethernet_hdr = (struct ethernet_header*)(pkt_content);
		//check if is acceptable packet
		if (ntohs(ethernet_hdr->ethernet_type) != ETHERNET_ARP)
			continue;
		int i;
		for (i = 0; i < 6; i++)
		{
			if (ethernet_hdr->destination_mac[i] != local_mac[i])
				break;
		}
		if (i < 6)
			continue;

		switch (ntohs(ethernet_hdr->ethernet_type))
		{
			case ETHERNET_ARP:
				printf("get arp reply!!!\n");
				destination_mac =   network_arp_recv(pkt_content + sizeof(struct ethernet_header));
				break;
			case ETHERNET_RARP:
				break;
		}

		if (destination_mac != NULL)
		{
			return destination_mac;
			break;
		}
	}

}

DWORD WINAPI datalink_send(LPVOID pM)
{
	open_device();

	while ( true )
	{
		//send to buffer2
		sendlock2.lock();
		if (SENDBUFFER2.empty == false)
		{
			ethernet_send_packet
		(SENDBUFFER2.pool[SENDBUFFER2.tail], SENDBUFFER2.destination_mac[SENDBUFFER2.tail], SENDBUFFER2.type[SENDBUFFER2.tail], SENDBUFFER2.ip_size_of_packet[SENDBUFFER2.tail]);
			
			SENDBUFFER2.tail = (SENDBUFFER2.tail + 1) % NUM_QUE;
			SENDBUFFER2.full = false;
		}
		if (SENDBUFFER2.head == SENDBUFFER2.tail)
			SENDBUFFER2.empty = true;
		sendlock2.unlock();
	}

	close_device();
}