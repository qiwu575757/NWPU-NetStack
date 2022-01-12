#include "TCP.h"

extern int	host;//���ڱ�ʾ�ͻ��˺ͷ�������
extern u_int8_t local_ip[4];
extern u_int16_t  local_port;
extern u_int16_t  server_port;

TCPSocket* tcp_socket()
{
	TCPSocket* socketid = (TCPSocket*)malloc(sizeof(TCPSocket));

	srand((unsigned)time(NULL));//��ʼ���������
	int k;
	for (k = 0; k < 4; k++)
		socketid->local_ip[k] = local_ip[k];

	switch (host)
	{
	case CLIENT:
		socketid->local_port = 49152 + rand() % 16023;
		break;
	case SERVER:
		socketid->local_port = -1;
		break;
	default:
		printf("[TCP]	wrong host!!!\n");
		break;
	}
	for (k = 0; k < 4; k++)
		socketid->target_ip[k] = 0;
	socketid->target_port = -1;
	socketid->sock_type = SOCK_STREAM;

	return socketid;
}

int tcp_close(TCPSocket* socketid)
{
	//�ͷ�udpͨ����Ԫ��
	free(socketid);

	return 1;
}