#include "Ethernet_recv.h"
#include "Ethernet_send.h"
#include "IPV4_send.h"
#include"ARP_Cache_Table.h"
#include "IPV4_recv.h"
#include "UDP_send.h"
#include "file_recv_send.h"

int main()
{
	//initial the arp_table
	init_arp_table();
	output_arp_table();
	init_buffer();

	//send data thread
	CreateThread(NULL, 0, read_from_file, NULL, 0, NULL);
	CreateThread(NULL, 0, udp_send, NULL, 0, NULL);
	CreateThread(NULL, 0, ip_send, NULL, 0, NULL);
	CreateThread(NULL, 0, datalink_send, NULL, 0, NULL);

	//receive data theread 
	CreateThread(NULL, 0, read_from_file, NULL, 0, NULL);
	CreateThread(NULL, 0, ipv4_distribute, NULL, 0, NULL);
	CreateThread(NULL, 0, datalink_distribute, NULL, 0, NULL);
	CreateThread(NULL, 0, datalink_receive, NULL, 0, NULL);

	while (1);

	return 0;
}