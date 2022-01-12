#include "Network_IPV4_send.h"

int main()
{
	CreateThread(NULL, 0, read_from_file, NULL, 0, NULL);//create thread to read data from file
	CreateThread(NULL, 0, ip_send, NULL, 0, NULL);//create thread to send data ethnet
	while (1);

	return 0;
}