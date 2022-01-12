#include"Network_ARP_send.h"
#include"Ethernet.h"
#include"Resource.h"
#include"Network_IPV4_send.h"

extern u_int8_t local_mac[6];
extern u_int8_t local_ip[4];
extern int ethernet_upper_len;

u_int8_t arp_buffer[MAX_SIZE];
extern sendbuffer2 SENDBUFFER2;

void load_arp_packet(u_int8_t *destination_ip)
{
	struct arp_pkt *arp_packet = (struct arp_pkt *)(arp_buffer);
	arp_packet->hardware_type = htons(ARP_HARDWARE);
	arp_packet->protocol_type = htons(ETHERNET_IP);
	arp_packet->hardware_addr_length = 6;
	arp_packet->protocol_addr_length = 4;
	arp_packet->op_code = htons(ARP_REQUEST);
	int i;
	for (i = 0; i < 6; i++)
	{
		arp_packet->source_mac[i] = local_mac[i];
	}
	for (i = 0; i < 4; i++)
	{
		arp_packet->source_ip[i] = local_ip[i];
	}

	for (i = 0; i < 6; i++)
	{
		arp_packet->destination_mac[i] = 0x00;
	}
	for (i = 0; i < 4; i++)
	{
		arp_packet->destination_ip[i] = destination_ip[i];
	}
}


void network_arp_send(u_int8_t *destination_ip, u_int8_t *ethernet_dest_mac)//将arp请求报文送入发送队列2
{
	load_arp_packet(destination_ip);
	u_int32_t ethernet_upper_len = sizeof(struct arp_pkt);

	SENDBUFFER2.ip_size_of_packet[SENDBUFFER2.head] = ethernet_upper_len;
	for (int j = 0; j < 6; j++)
	{
		SENDBUFFER2.destination_mac[SENDBUFFER2.head][j] = *(ethernet_dest_mac + j);
	}
	SENDBUFFER2.type[SENDBUFFER2.head] = ETHERNET_ARP;
	for (int i = 0; i < ethernet_upper_len; i++)
	{
		SENDBUFFER2.pool[SENDBUFFER2.head][i] = arp_buffer[i];
	}
	SENDBUFFER2.head = (SENDBUFFER2.head + 1) % NUM_QUE;
	SENDBUFFER2.empty = false;

	if (SENDBUFFER2.head == SENDBUFFER2.tail)
		SENDBUFFER2.full = true;
}