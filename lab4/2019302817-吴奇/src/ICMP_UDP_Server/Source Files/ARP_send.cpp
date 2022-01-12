#include"ARP_send.h"                                
#include"Ethernet_send.h"

extern u_int8_t local_mac[6];
extern u_int8_t local_ip[4];
extern int ethernet_upper_len;

u_int8_t arp_buffer[MAX_SIZE];
extern std::mutex sendlock1;
extern sendbuffer1 SENDBUFFER1;     

void load_arp_packet(u_int8_t* destination_ip, u_int16_t op_code)
{
	struct arp_pkt* arp_packet = (struct arp_pkt*)(arp_buffer);
	arp_packet->hardware_type = htons(ARP_HARDWARE);
	arp_packet->protocol_type = htons(ETHERNET_IP);
	arp_packet->hardware_addr_length = 6;
	arp_packet->protocol_addr_length = 4;
	arp_packet->op_code = op_code; 
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

void arp_req_send(u_int8_t* destination_ip, u_int8_t* ethernet_dest_mac)//将arp请求报文送入发送队列1
{
	printf("[ARP]	SEND ARP REQUEST\n");
	load_arp_packet(destination_ip, htons(ARP_REQUEST));
	u_int32_t ethernet_upper_len = sizeof(struct arp_pkt);

	ethernet_send_packet(arp_buffer, ethernet_dest_mac, ETHERNET_ARP, ethernet_upper_len);
}

void arp_res_send(u_int8_t* destination_ip, u_int8_t* ethernet_dest_mac)
{
	printf("[ARP]	SEND ARP RESPONSE\n");
	struct arp_pkt* arp_packet = (struct arp_pkt*)arp_buffer;
	load_arp_packet(destination_ip, htons(ARP_REPLY));
	int i;
	for (i = 0; i < 6; i++)
	{
		arp_packet->destination_mac[i] = ethernet_dest_mac[i];
	}

	ethernet_upper_len = sizeof(struct arp_pkt);
	//send the packet
	ethernet_send_packet(arp_buffer, ethernet_dest_mac, ETHERNET_ARP, ethernet_upper_len);
}