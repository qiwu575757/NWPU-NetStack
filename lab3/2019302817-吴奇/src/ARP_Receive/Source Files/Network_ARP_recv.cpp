#include "Network_ARP_recv.h"
#include "Resource.h"
#include "ARP_Cache_Table.h"

extern u_int8_t local_ip[4];
extern u_int8_t local_mac[6];

int is_accept_arp_packet(struct arp_pkt *arp_packet)
{
	if (ntohs(arp_packet->hardware_type) != ARP_HARDWARE)
		return 0;
	if (ntohs(arp_packet->protocol_type) != ETHERNET_IP)
		return 0;
	int i;
	for (i = 0; i < 4; i++)
	{
		if (arp_packet->destination_ip[i] != local_ip[i])
			return 0;
	}
	if (ntohs(arp_packet->op_code) == ARP_REQUEST)//arp ������
	{
		for (i = 0; i < 6; i++)
		{
			if (arp_packet->destination_mac[i] != 0x00)
				return 0;
		}
	}
	else if (ntohs(arp_packet->op_code) == ARP_REPLY)
	{
		for (i = 0; i < 6; i++)
		{
			if (arp_packet->destination_mac[i] != local_mac[i])
				return 0;
		}
	}

	//add source ip and source mac
	struct arp_node *element;
	if (!is_existed_ip(arp_packet->source_ip))//��ǰarp���������û�ж�Ӧ source_ip and source_mac
	{
		element = make_arp_node(arp_packet->source_ip, arp_packet->source_mac, STATIC_STATE);
		insert_arp_node(element);
	}

	return 1;
}

u_int8_t* network_arp_recv(u_int8_t *arp_buffer)
{
	struct arp_pkt *arp_packet = (struct arp_pkt *)arp_buffer;
	if (!is_accept_arp_packet(arp_packet))
		return NULL;
	output(arp_packet);
	output_arp_table();

	/*if arp_request so reply
	else if arp_reply no operation
	*/

	if (ntohs(arp_packet->op_code) == ARP_REQUEST)
	{
		network_arp_send(arp_packet->source_ip, arp_packet->source_mac);
		return NULL;
	}
	else if (ntohs(arp_packet->op_code) == ARP_REPLY)
	{
		return arp_packet->source_mac;
	}
}



void output(struct arp_pkt *arp_packet)
{
	printf("--------ARP Protocol---------\n");
	printf("Hardware Type: %04x\n", ntohs(arp_packet->hardware_type));
	printf("Protocol Type: %04x\n", ntohs(arp_packet->protocol_type));
	printf("Operation Code: %04x\n", ntohs(arp_packet->op_code));
	printf("Source MAC: ");
	int i;
	for (i = 0; i < 6; i++)
	{
		if (i)printf("-");
		printf("%02x", arp_packet->source_mac[i]);
	}
	printf("\nSourcee IP: ");
	for (i = 0; i < 4; i++)
	{
		if (i)printf(".");
		printf("%d", arp_packet->source_ip[i]);
	}
	printf("\n");
}