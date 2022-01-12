#include "Ethernet_recv.h"
#include "ARP_recv.h"

u_int32_t packet_number = 1;

extern u_int8_t local_mac[6];
extern pcap_t* handle;
extern recvbuffer1 RECVBUFFER1;
extern recvbuffer2 RECVBUFFER2;
extern recvbuffer3 RECVBUFFER3;
extern std::mutex recvlock1;//定义互斥锁用于对缓冲区的互斥访问
extern std::mutex recvlock2;
extern std::mutex recvlock3;


void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	int len = packet_header->len;
	if (!is_accept_ethernet_packet((u_int8_t*)packet_content, len))
	{
		return;
	}

	struct ethernet_header* ethernet_hdr = (struct ethernet_header*)packet_content;
	u_int16_t ethernet_type = ntohs(ethernet_hdr->ethernet_type);

	printf("[Ethernet]	Capture %d packet\n", packet_number++);
	printf("[Ethernet]	Capture time: %d %d\n", packet_header->ts.tv_sec, packet_header->ts.tv_usec);
	printf("[Ethernet]	Packet length: %d\n", packet_header->len);
	printf("--------------------------Ethernet Protocol------------------------\n");
	printf("[Ethernet]	Ethernet type:  %04x\n", ethernet_type);
	printf("[Ethernet]	MAC source address: ");
	output_mac(ethernet_hdr->source_mac);
	printf("\n");
	printf("[Ethernet]	MAC destination address: ");
	output_mac(ethernet_hdr->destination_mac);
	printf("\n");

	u_int8_t* upper_buffer = (u_int8_t*)(packet_content + sizeof(ethernet_header));

	int k = 0;
	recvlock1.lock();
	if (RECVBUFFER1.full == false)
	{
		for (u_int8_t* ip_buffer = (u_int8_t*)(packet_content); ip_buffer != (u_int8_t*)(packet_content + packet_header->len - 4); ip_buffer++)
		{
			RECVBUFFER1.pool[RECVBUFFER1.head][k++] = *ip_buffer;
		}
		RECVBUFFER1.length[RECVBUFFER1.head] = k;
		RECVBUFFER1.ethernet_type[RECVBUFFER1.head] = ethernet_type;
		RECVBUFFER1.head = (RECVBUFFER1.head + 1) % NUM_QUE;
		RECVBUFFER1.empty = false;
	}
	if (RECVBUFFER1.head == RECVBUFFER1.tail)
		RECVBUFFER1.full = true;
	recvlock1.unlock();
	printf("-------------------End of Ethernet Protocol----------------\n");
}

DWORD WINAPI datalink_receive(LPVOID pM)
{
	open_device();

	pcap_loop(handle, NULL, ethernet_protocol_packet_callback, NULL);

	close_device();

	return 0;
}

DWORD WINAPI datalink_distribute(LPVOID pM)
{
	while (true)
	{
		recvlock1.lock();
		if ( RECVBUFFER1.empty == false )
		{
			printf("--------------------------DATALINK DISTRIBUTE------------------------\n");
			switch (RECVBUFFER1.ethernet_type[RECVBUFFER1.tail])
			{
				case 0x0800:
					printf("Upper layer protocol: IPV4\n");

					recvlock2.lock();
					if (RECVBUFFER2.full == false)
					{
						for ( int k = 0; k < RECVBUFFER1.length[RECVBUFFER1.tail] - sizeof(ethernet_header); k++ )
						{
							RECVBUFFER2.pool[RECVBUFFER2.head][k] = RECVBUFFER1.pool[RECVBUFFER1.tail][k+ sizeof(ethernet_header)];
						}
						RECVBUFFER2.head = (RECVBUFFER2.head + 1) % NUM_QUE;
						RECVBUFFER2.empty = false;
					}
					if (RECVBUFFER2.head == RECVBUFFER2.tail)
						RECVBUFFER2.full = true;
					recvlock2.unlock();
					break;
				case 0x0806:
					printf("Upper layer protocol: ARP\n");
					arp_recv();
					break;
				case 0x8035:
					printf("Upper layer protocol: RARP\n");
					//network_rarp_recv();
					break;
				case 0x814c:
					printf("Upper layer protocol: SNMP\n");
					//network_snmp_recv();
					break;
				case 0x8137:
					printf("Upper layer protocol: IPX(Internet Packet Exchange)\n");
					//network_ipx_recv();
					break;
				case 0x86DD:
					printf("Upper layer protocol: IPV6\n");
					//network_ipv6_recv();
					break;
				case 0x880B:
					printf("Upper layer protocol: PPP\n");
					//network_ppp_recv();
					break;
				default:
					break;
			}

			RECVBUFFER1.tail = (RECVBUFFER1.tail + 1) % NUM_QUE;
			RECVBUFFER1.full = false;
			if (RECVBUFFER1.head == RECVBUFFER1.tail)
				RECVBUFFER1.empty = true;

			printf("-----------------------END OF DATALINK DISTRIBUTE------------------------\n");
		}

		recvlock1.unlock();
	}
}