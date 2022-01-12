#include "TCP.h"

extern int	host;//用于表示客户端和服务器端
extern u_int8_t local_ip[4];
extern u_int16_t  local_port;
extern u_int16_t  server_port;

TCPSocket* tcp_socket()
{
	TCPSocket* socketid = (TCPSocket*)malloc(sizeof(TCPSocket));
	if (socketid == NULL)
	{
		printf("内存分配失败！！！\n");

		return NULL;
	}
	srand((unsigned)time(NULL));//初始化随机种子
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

//绑定服务器ＩＰ地址和端口号,仅供服务器端调用
int tcp_bind(TCPSocket* socketid, u_int8_t* server_ip, u_int16_t server_port)
{
	int k;
	for (k = 0; k < 4; k++)
	{
		socketid->local_ip[k] = server_ip[k];
	}
	socketid->local_port = server_port;

	return 1;
}

int tcp_close(TCPSocket* socketid)
{
	//释放udp通信五元组
	free(socketid);

	return 1;
}