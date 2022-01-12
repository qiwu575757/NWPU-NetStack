#include "ARP_Cache_Table.h"
#include "Resource.h"
#include "Ethernet.h"
#include "Network_IPV4_send.h"
#include "Header_Include.h"

int main()
{
	//initial the arp_table
	init_arp_table();
	output_arp_table();
	init_sendbuffer1();
	init_sendbuffer2();

	CreateThread(NULL, 0, datalink_send, NULL, 0, NULL);//create thread to read data from file
	CreateThread(NULL, 0, read_from_file, NULL, 0, NULL);//create thread to read data from file
	CreateThread(NULL, 0, ip_send, NULL, 0, NULL);//create thread to send data ethnet
	while (1);

	return 0;
}