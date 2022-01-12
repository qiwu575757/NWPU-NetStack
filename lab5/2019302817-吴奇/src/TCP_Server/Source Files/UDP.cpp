#include"UDP.h"

extern u_int8_t local_ip[4];
extern u_int16_t  local_port;
extern u_int16_t  server_port;

//构造好一个通信五元组数据结构变量，并完成初始化；
UDPSocket* udp_socket()
{
	UDPSocket* socketid = (UDPSocket*)malloc(sizeof(UDPSocket));
	if (socketid == NULL)
	{
		printf("内存分配失败\n");
		return NULL;
	}
	int k;
	for (k = 0; k < 4; k++)
	{
		socketid->local_ip[k] = local_ip[k];
	}
	socketid->local_port = local_port;
	for (k = 0; k < 4; k++)
	{
		socketid->target_ip[k] = 0;
	}
	socketid->target_port = -1;//使用u_int16_t，-1代表65535，但是影响不大
	socketid->sock_type = SOCK_DGRAM;//表示数据报类型

	return socketid;
}

//绑定服务器ＩＰ地址和端口号,仅供服务器端调用
int bind(UDPSocket* socketid, u_int8_t* server_ip, u_int16_t server_port)
{
	int k;
	for (k = 0; k < 4; k++)
	{
		socketid->local_ip[k] = server_ip[k];
	}
	socketid->local_port = server_port;

	return 1;
}

int udp_close(UDPSocket* socketid)
{
	//释放udp通信五元组
	free(socketid);

	return 1;
}