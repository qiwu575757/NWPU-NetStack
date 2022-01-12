#include "Ethernet.h"

u_int32_t size_of_packet = 0;
u_int8_t buffer[MAX_SIZE];

extern pcap_t* handle;
extern u_int8_t local_mac[6];
extern std::mutex sendlock1;
extern sendbuffer1 SENDBUFFER1;

void load_ethernet_header(u_int8_t* destination_mac, u_int16_t ethernet_type)
{
	struct ethernet_header* hdr = (struct ethernet_header*)buffer;
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

int load_ethernet_data(u_int8_t* buffer, u_int8_t* upper_buffer, int len)
{
	printf("LOAD ETHERNET DATA\n");
	if (len > 1500)
	{
		printf("[ETHERNET]	IP buffer is too large. So we stop the procedure.");
		return -1;
	}

	int i;
	for (i = 0; i < len; i++)
	{
		*(buffer + i) = *(upper_buffer + i);
		//printf("%c", *(buffer + i));
	}

	//add a serial 0 at the end
	while (len < 46)
	{
		*(buffer + len) = 0;
		len++;
	}

	//generate_crc32_table();
	u_int32_t crc = calculate_crc(buffer, len);

	*(u_int32_t*)(buffer + len) = crc;
	size_of_packet += len + 4;
	return 1;
}

int ethernet_send_packet(u_int8_t* upper_buffer, u_int8_t* destination_mac, u_int16_t ethernet_type, u_int32_t ip_size_of_packet)
{
	open_device();
	load_ethernet_header(destination_mac, ethernet_type);
	load_ethernet_data(buffer + sizeof(struct ethernet_header), upper_buffer, ip_size_of_packet);
	printf("[ETHERNET]	SIZE OF PACKET is %d\n", size_of_packet);

	if (pcap_sendpacket(handle, (const u_char*)buffer, size_of_packet) != 0)
	{
		printf("[ETHERNET]	Sending failed..\n");
		return -1;
	}
	else
	{
		printf("[ETHERNET]	Sending Succeed..\n");
		return 1;
	}
	close_device();
}

DWORD WINAPI datalink_send(LPVOID pM)
{
	open_device();

	while (1)
	{
		//send to buffer1
		sendlock1.lock();
		if (SENDBUFFER1.empty == false)
		{
			printf("[ETHERNET]	SEND ETHERNET PACKET\n");
			//show the data for debug;
			//for (u_int8_t* p = (u_int8_t*)(SENDBUFFER1.pool[SENDBUFFER1.tail] + sizeof(ip_header)); p != (SENDBUFFER1.pool[SENDBUFFER1.tail] + sizeof(ip_header))+ SENDBUFFER1.ip_size_of_packet[SENDBUFFER1.tail]; p++)
			//{
			//	printf("%c", *p);
			//}
			//printf("\n");
			//printf("----------------------\n");

			ethernet_send_packet
			(SENDBUFFER1.pool[SENDBUFFER1.tail], SENDBUFFER1.destination_mac[SENDBUFFER1.tail], SENDBUFFER1.type[SENDBUFFER1.tail], SENDBUFFER1.ip_size_of_packet[SENDBUFFER1.tail]);

			SENDBUFFER1.tail = (SENDBUFFER1.tail + 1) % NUM_QUE;
			SENDBUFFER1.full = false;
		}
		if (SENDBUFFER1.head == SENDBUFFER1.tail)
			SENDBUFFER1.empty = true;
		sendlock1.unlock();
	}

	close_device();
}