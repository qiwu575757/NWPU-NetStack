#include "Ethernet_recv.h"
#include "Ethernet_send.h"
#include "IPV4_send.h"
#include"ARP_Cache_Table.h"
#include "IPV4_recv.h"
#include "UDP_send.h"
#include "file_recv_send.h"
#include "TCP_recv.h"

int main()
{
	//initial the arp_table
	init_arp_table();
	output_arp_table();
	init_buffer();

	//receive data theread 
	CreateThread(NULL, 0, write_to_file, NULL, 0, NULL);
	CreateThread(NULL, 0, tcp_recv, NULL, 0, NULL);
	CreateThread(NULL, 0, ipv4_distribute, NULL, 0, NULL);
	CreateThread(NULL, 0, datalink_distribute, NULL, 0, NULL);
	CreateThread(NULL, 0, datalink_receive, NULL, 0, NULL);

	//根据需要选择创建哪些线程
	//send data thread
	//CreateThread(NULL, 0, read_from_file, NULL, 0, NULL);
	//CreateThread(NULL, 0, udp_send, NULL, 0, NULL);
	CreateThread(NULL, 0, ip_send, NULL, 0, NULL);
	CreateThread(NULL, 0, datalink_send, NULL, 0, NULL);


	while (1);

	return 0;
}