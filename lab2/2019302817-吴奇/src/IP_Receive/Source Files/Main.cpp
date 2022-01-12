#include "Network_ipv4_recv.h"

int main()
{
	printf("test1\n");
	CreateThread(NULL, 0, datalink_receive, NULL, 0, NULL);
	CreateThread(NULL, 0, ipv4_receive, NULL, 0, NULL);
	CreateThread(NULL, 0, ipv4_writetofile, NULL, 0, NULL);
	while (1);

	return 0;
}