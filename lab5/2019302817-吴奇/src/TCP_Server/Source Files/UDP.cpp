#include"UDP.h"

extern u_int8_t local_ip[4];
extern u_int16_t  local_port;
extern u_int16_t  server_port;

//�����һ��ͨ����Ԫ�����ݽṹ����������ɳ�ʼ����
UDPSocket* udp_socket()
{
	UDPSocket* socketid = (UDPSocket*)malloc(sizeof(UDPSocket));
	if (socketid == NULL)
	{
		printf("�ڴ����ʧ��\n");
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
	socketid->target_port = -1;//ʹ��u_int16_t��-1����65535������Ӱ�첻��
	socketid->sock_type = SOCK_DGRAM;//��ʾ���ݱ�����

	return socketid;
}

//�󶨷������ɣе�ַ�Ͷ˿ں�,�����������˵���
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
	//�ͷ�udpͨ����Ԫ��
	free(socketid);

	return 1;
}