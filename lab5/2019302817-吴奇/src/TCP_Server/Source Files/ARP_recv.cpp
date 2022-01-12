#include"ARP_recv.h"
#include"ARP_send.h"
#include"ARP_Cache_Table.h"

extern pcap_t* handle;
extern std::mutex recvlock3;
extern recvbuffer3 RECVBUFFER3;
extern recvbuffer1 RECVBUFFER1;

extern u_int8_t local_mac[6];
extern u_int8_t local_ip[4];
extern u_int8_t target_ip[4];

void output(struct arp_pkt* arp_packet)
{
	printf("--------------ARP Protocol---------------\n");
	printf("[ARP]	Hardware Type: %04x\n", arp_packet->hardware_type);
	printf("[ARP]	Protocol Type: %04x\n", arp_packet->protocol_type);
	printf("[ARP]	Operation Code: %04x\n", arp_packet->op_code);
	printf("[ARP]	Source MAC: ");
	int i;
	for (i = 0; i < 6; i++)
	{
		if (i)
			printf("-");
		printf("%02x", arp_packet->source_mac[i]);
	}
	printf("\n");
	printf("[ARP]	Source IP: ");
	for (i = 0; i < 4; i++)
	{
		if (i)printf(".");
		printf("%d", arp_packet->source_ip[i]);
	}
	printf("\n");

}

int is_accept_arp_packet(struct arp_pkt* arp_packet)
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
	if (ntohs(arp_packet->op_code) == ARP_REQUEST)//arp 请求报文
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
	struct arp_node* element;
	if (!is_existed_ip(arp_packet->source_ip))//当前arp缓存队列中没有对应 source_ip and source_mac
	{
		element = make_arp_node(arp_packet->source_ip, arp_packet->source_mac, STATIC_STATE);
		insert_arp_node(element);
	}

	return 1;
}

u_int8_t* network_arp_recv(u_int8_t* arp_buffer)
{
	struct arp_pkt* arp_packet = (struct arp_pkt*)(arp_buffer);

	if (is_accept_arp_packet(arp_packet))
	{
		printf("\n----------test0----------\n");
		output(arp_packet);
		output_arp_table();
		return arp_packet->source_mac;
	}
	return NULL;
}

u_int8_t* arp_res_recv(u_int8_t* destination_ip)
{
	//wait for replying, get the destination mac
	struct pcap_pkthdr* pkt_hdr;
	u_int8_t* pkt_content;
	u_int8_t* destination_mac = NULL;
	bool end = false;

	while (end == false)
	{
		destination_mac = is_existed_ip(destination_ip);
		if (destination_mac != NULL)
		{
			printf("[ARP]	GET DESTMAC BY OTHER ARP REQUEST\n");
			end = true;
			break;
		}

		recvlock3.lock();
		if (RECVBUFFER3.empty == false)
		{
			//get the ethernet header
			struct ethernet_header* ethernet_hdr = (struct ethernet_header*)(RECVBUFFER3.pool[RECVBUFFER3.tail]);
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
				destination_mac = network_arp_recv(RECVBUFFER3.pool[RECVBUFFER3.tail] + sizeof(struct ethernet_header));
				RECVBUFFER3.tail = (RECVBUFFER3.tail + 1) % NUM_QUE;
				RECVBUFFER3.full = false;
				if (RECVBUFFER3.head == RECVBUFFER3.tail)
					RECVBUFFER3.empty = true;
				break;
			case ETHERNET_RARP:
				break;
			}

			if (destination_mac != NULL)
			{
				end = true;
			}
		}
		recvlock3.unlock();
	}

	return destination_mac;
}

void arp_recv()
{
	printf("--------------------------ARP RECV------------------------\n");
	struct arp_pkt* arp_packet = (struct arp_pkt*)(RECVBUFFER1.pool[RECVBUFFER1.tail] + sizeof(ethernet_header));
	if (!is_accept_arp_packet(arp_packet))
		return;
	output(arp_packet);
	output_arp_table();

	/*if arp_request so reply
		else if arp_reply no operation
	*/

	if (ntohs(arp_packet->op_code) == ARP_REQUEST)//接收arp请求报文并发送响应
	{
		arp_res_send(arp_packet->source_ip, arp_packet->source_mac);
	}
	else if (ntohs(arp_packet->op_code) == ARP_REPLY)//接收arp响应报文
	{
		printf("[ARP]	RECEIVE ARP RESPONSE\n");
		recvlock3.lock();
		if (RECVBUFFER3.full == false)
		{
			for (int k = 0; k < RECVBUFFER1.length[RECVBUFFER1.tail]; k++)
			{
				RECVBUFFER3.pool[RECVBUFFER3.head][k] = RECVBUFFER1.pool[RECVBUFFER1.tail][k];
			}
			RECVBUFFER3.head = (RECVBUFFER3.head + 1) % NUM_QUE;
			RECVBUFFER3.empty = false;
		}
		if (RECVBUFFER3.head == RECVBUFFER3.tail)
			RECVBUFFER3.full = true;
		recvlock3.unlock();
	}

	printf("--------------------------END OF ARP RECV------------------------\n");
	return;
}