#include "TCP_recv.h"
#include "UDP_recv.h"
#include "IPV4_send.h"

extern int	host;//用于表示客户端和服务器端
extern std::mutex sendlock2;
extern std::mutex recvlock4;
extern std::mutex recvlock5;
extern recvbuffer2 RECVBUFFER2;
extern recvbuffer4 RECVBUFFER4;
extern recvbuffer5 RECVBUFFER5;
extern sendbuffer2 SENDBUFFER2;

extern int server_recvstate;
extern TCB* tcb;
extern u_int16_t local_port;
extern u_int8_t local_ip[4];
extern u_int16_t server_port;
extern u_int8_t server_ip[4];
extern u_int8_t target_ip[4];
extern u_int16_t  client_port;
extern u_int8_t client_ip[4];

u_int8_t tcp_recv_buffer[1500] = { 0 };
int recv_tcpdata_index = 0;
int send_tcpdata_index = 0;


void update_thebuffer5()
{
	//update the datalink_ip_receivequeue
	if (RECVBUFFER5.full == false)
	{
		RECVBUFFER5.tail = (RECVBUFFER5.tail + 1) % NUM_QUE;
		RECVBUFFER5.full = false;
	}
	if (RECVBUFFER5.head == RECVBUFFER5.tail)
		RECVBUFFER5.empty = true;
}

void tcp_readfrom_ip()
{
	while (true)
	{
		recvlock5.lock();
		if (RECVBUFFER5.full == false)
		{
			//tcp报文由于mss保证了不会发生分片，无需对ip数据报进行分片重组
			printf("[TCP]	recvbuffer5 receive data\n");
			struct ip_header* ip_hdr = (struct ip_header*)RECVBUFFER2.pool[RECVBUFFER2.tail];
			int k;
			for (k = 0; k < ntohs(ip_hdr->total_length) - sizeof(ip_header); k++)
			{
				RECVBUFFER5.pool[RECVBUFFER5.head][k] = RECVBUFFER2.pool[RECVBUFFER2.tail][k + sizeof(ip_header)];
			}
			RECVBUFFER5.size_of_packet[RECVBUFFER5.head] = k;
			RECVBUFFER5.head = (RECVBUFFER5.head + 1) % NUM_QUE;
			RECVBUFFER5.empty = false;
			if (RECVBUFFER5.head == RECVBUFFER5.tail)
				RECVBUFFER5.full = true;
			recvlock5.unlock();
			break;
		}

		recvlock5.unlock();
	}
}

int tcp_listen(TCPSocket* socketid, u_int8_t* buf, int buflen)
{
	int k;
	//load tcp data to [pseheader+tcpdata] buffer
	load_data_to_buffer(tcp_recv_buffer + sizeof(tcp_pseheader), buf, buflen);

	if (host != SERVER)
		return -1;
	srand((unsigned)time(NULL));
	tcb = (TCB*)malloc(sizeof(TCB));
	//tcb init
	tcb->server_initial_seq = rand() % 10000;
	tcb->server_mss = MSS;
	tcb->recv_window_size = 1;
	tcb->recv_cache_size = NUM_QUE;
	tcb->send_window_size = 1;
	tcb->send_cache_size = NUM_QUE;

	tcp_header* tcp_hdr = (tcp_header*)(tcp_recv_buffer + sizeof(tcp_pseheader));
	tcp_pseheader* tcp_psehdr = (tcp_pseheader*)tcp_recv_buffer;

	//tcp pseheader init
	for (k = 0; k < 4; k++)
	{
		tcp_psehdr->dest_ip[k] = local_ip[k];
		tcp_psehdr->src_ip[k] = target_ip[k];
	}
	tcp_psehdr->length = buflen;
	tcp_psehdr->protocol = 6;
	tcp_psehdr->reserve = 0;

	//receive first handmake
	if ((tcp_hdr->flags & SYN) != SYN)
	{
		printf("[TCP]No SYN bit!\n");
		return -1;
	}
	if (tcp_hdr->dest_port != socketid->local_port) {
		printf("[TCP]Wrong Destination Port! %d-%d\n", tcp_hdr->dest_port, socketid->local_port);
		return -1;
	}
	u_int16_t checknum = calculate_check_sum((ip_header*)tcp_recv_buffer, buflen + sizeof(tcp_psehdr));
	if (checknum != 0xffff && checknum != 0)
	{
		printf("[TCP]	check num = %d\n", checknum);
		printf("[TCP]	Wrong Checksum!\n");
		return -1;
	}
	if (tcp_hdr->options[0] != 2 || tcp_hdr->options[1] != 4)	//未携带MSS选项字段
	{
		printf("[TCP]Wrong header options! %d-%d\n", tcp_hdr->options[0], tcp_hdr->options[1]);
		return -1;
	}
	tcb->client_initial_seq = tcp_hdr->sequence;
	tcb->client_mss = tcp_hdr->options[2] * 256 + tcp_hdr->options[3];

	printf("\n=============[TCP]成功接收第一次握手,syn=%d,seq=%d\n", (tcp_hdr->flags & SYN), tcp_hdr->sequence);
	//save the src ip and src port for the next send second handmake
	for (k = 0; k < 4; k++)
		client_ip[k] = tcp_psehdr->src_ip[k];
	client_port = tcp_hdr->src_port;

	return 1;
}

//用于发送挥手或者握手时的ack应答报文
int tcp_accept1(TCPSocket* socketid, int acklen, int send_type)
{
	if (host != SERVER)
	{
		printf("[TCP]	THE HOST IS INVALID\n");
		return -1;
	}
	tcp_header* tcp_hdr = (tcp_header*)(tcp_recv_buffer + sizeof(tcp_pseheader));
	tcp_pseheader* tcp_psehdr = (tcp_pseheader*)tcp_recv_buffer;
	int k;

	//tcp header init
	tcp_hdr->src_port = socketid->local_port;
	tcp_hdr->dest_port = socketid->target_port;
	tcp_hdr->sequence = tcb->server_initial_seq;
	tcp_hdr->confirmnum = tcb->client_initial_seq + acklen;
	tcp_hdr->header_length = (sizeof(tcp_header) / 4) << 4;
	tcp_hdr->flags = ACK;
	if (send_type == 1)
		tcp_hdr->flags += SYN;
	else if (send_type == 2)
		tcp_hdr->flags += FIN;

	tcp_hdr->window = tcb->recv_window_size;
	tcp_hdr->checknum = 0;
	tcp_hdr->urgent_pointer = 0;
	tcp_hdr->options[0] = 2;	//填写MSS选项字段
	tcp_hdr->options[1] = 4;
	tcp_hdr->options[2] = tcb->server_mss / 256;
	tcp_hdr->options[3] = tcb->server_mss % 256;

	//tcp pseheader init
	for (k = 0; k < 4; k++)
	{
		tcp_psehdr->dest_ip[k] = target_ip[k];
		tcp_psehdr->src_ip[k] = local_ip[k];
	}
	tcp_psehdr->length = sizeof(tcp_header);//响应报文数据部分为空
	tcp_psehdr->protocol = 6;
	tcp_psehdr->reserve = 0;
	tcp_hdr->checknum = calculate_check_sum((ip_header*)tcp_recv_buffer, tcp_psehdr->length + sizeof(tcp_psehdr));
	//send second handmake
	while (1)
	{
		sendlock2.lock();
		if (SENDBUFFER2.full == false)
		{
			SENDBUFFER2.size_of_packet[SENDBUFFER2.head] = tcp_psehdr->length;
			for (k = 0; k < SENDBUFFER2.size_of_packet[SENDBUFFER2.head]; k++)
			{
				SENDBUFFER2.pool[SENDBUFFER2.head][k] = tcp_recv_buffer[k + sizeof(tcp_pseheader)];
			}
			SENDBUFFER2.proto_type[SENDBUFFER2.head] = IPPROTO_TCP;
			SENDBUFFER2.head = (SENDBUFFER2.head + 1) % NUM_QUE;
			SENDBUFFER2.empty = false;
			if (SENDBUFFER2.head == SENDBUFFER2.tail)
				SENDBUFFER2.full = true;
			if (send_type == 0)
				printf("\n[TCP]成功发送第二次挥手,ACK = 1,seq=%d,ack=%d\n", tcp_hdr->sequence, tcp_hdr->confirmnum);
			else if (send_type == 1)
				printf("\n[TCP]成功发送第二次握手,SYN = 1, ACK = 1,seq=%d,ack=%d\n", tcp_hdr->sequence, tcp_hdr->confirmnum);
			else if (send_type == 2)
				printf("\n[TCP]成功发送第三次挥手,FIN = 1,ACK = 1,seq=%d,ack=%d\n", tcp_hdr->sequence, tcp_hdr->confirmnum);
			else if (send_type == 3)
			{
				send_tcpdata_index++;
				printf("\n[TCP]成功发送第%d个ACK应答,seq=%d,ack=%d\n", send_tcpdata_index, tcp_hdr->sequence, tcp_hdr->confirmnum);
			}
			sendlock2.unlock();
			break;
		}

		sendlock2.unlock();
	}
	tcb->client_initial_seq = tcp_hdr->sequence;
	tcb->client_mss = tcp_hdr->options[2] * 256 + tcp_hdr->options[3];

	return 1;
}

int tcp_accept2(TCPSocket* socketid, u_int8_t* buf, int buflen, int send_type)
{
	//load tcp data to [pseheader+tcpdata] buffer
	load_data_to_buffer(tcp_recv_buffer + sizeof(tcp_pseheader), buf, buflen);
	if (host != SERVER)
		return -1;
	tcp_header* tcp_hdr = (tcp_header*)(tcp_recv_buffer + sizeof(tcp_pseheader));
	tcp_pseheader* tcp_psehdr = (tcp_pseheader*)tcp_recv_buffer;

	int k;
	//tcp pseheader init
	for (k = 0; k < 4; k++)
	{
		tcp_psehdr->dest_ip[k] = local_ip[k];
		tcp_psehdr->src_ip[k] = client_ip[k];
	}
	tcp_psehdr->length = buflen;
	tcp_psehdr->protocol = 6;
	tcp_psehdr->reserve = 0;
	//receive third handmake
	if ((tcp_hdr->flags & ACK) != ACK)//第三次握手的ack位为1
	{
		printf("[TCP]No ACK bit!\n");
		return -1;
	}
	if (tcp_hdr->dest_port != socketid->local_port) {
		printf("[TCP]Wrong Destination Port! %d-%d\n", tcp_hdr->dest_port, socketid->local_port);
		return -1;
	}
	u_int16_t checknum = calculate_check_sum((ip_header*)tcp_recv_buffer, buflen + sizeof(tcp_psehdr));
	if (checknum != 0xffff && checknum != 0)
	{
		printf("[TCP]	check num = %d\n", checknum);
		printf("[TCP]	Wrong Checksum!\n");
		return -1;
	}
	if (tcp_hdr->options[0] != 2 || tcp_hdr->options[1] != 4)	//未携带MSS选项字段
	{
		printf("[TCP]Wrong header options! %d-%d\n", tcp_hdr->options[0], tcp_hdr->options[1]);
		return -1;
	}
	tcb->client_initial_seq = tcp_hdr->sequence;
	tcb->client_mss = tcp_hdr->options[2] * 256 + tcp_hdr->options[3];
	recv_tcpdata_index++;
	if (send_type == 0)
		printf("\n=============[TCP]成功接收第三次握手,第%d个ACK应答，ACK=1,seq=%d,ack=%d\n", recv_tcpdata_index, tcp_hdr->sequence, tcp_hdr->confirmnum);
	else
		printf("\n=============[TCP]成功接收第四次挥手,第%d个ACK应答，ACK=1,seq=%d,ack=%d\n", recv_tcpdata_index, tcp_hdr->sequence, tcp_hdr->confirmnum);

	return 1;
}

int tcp_recvfrom(TCPSocket* socketid, u_int8_t* buf, int buflen)
{
	//load tcp data to [pseheader+tcpdata] buffer
	load_data_to_buffer(tcp_recv_buffer + sizeof(tcp_pseheader), buf, buflen);
	if (host != SERVER)
		return -1;
	tcp_header* tcp_hdr = (tcp_header*)(tcp_recv_buffer + sizeof(tcp_pseheader));
	tcp_pseheader* tcp_psehdr = (tcp_pseheader*)tcp_recv_buffer;

	//receive data transfer
	if (((tcp_hdr->flags & ACK) != ACK) && ((tcp_hdr->flags & FIN) != FIN))
	{
		printf("[TCP]No ACK AND FIN bit!\n");
		return -1;
	}
	int k;
	//tcp pseheader init
	for (k = 0; k < 4; k++)
	{
		tcp_psehdr->dest_ip[k] = local_ip[k];
		tcp_psehdr->src_ip[k] = client_ip[k];
	}
	tcp_psehdr->length = buflen;
	tcp_psehdr->protocol = 6;
	tcp_psehdr->reserve = 0;

	if (tcp_hdr->dest_port != socketid->local_port) {
		printf("[TCP]Wrong Destination Port! %d-%d\n", tcp_hdr->dest_port, socketid->local_port);
		return -1;
	}
	u_int16_t checknum = calculate_check_sum((ip_header*)tcp_recv_buffer, buflen + sizeof(tcp_psehdr));
	if (checknum != 0xffff && checknum != 0)
	{
		printf("[TCP]	check num = %d\n", checknum);
		printf("[TCP]	Wrong Checksum!\n");
		return -1;
	}
	if (tcp_hdr->options[0] != 2 || tcp_hdr->options[1] != 4)	//未携带MSS选项字段
	{
		printf("[TCP]Wrong header options! %d-%d\n", tcp_hdr->options[0], tcp_hdr->options[1]);
		return -1;
	}
	tcb->client_initial_seq = tcp_hdr->sequence;
	tcb->client_mss = tcp_hdr->options[2] * 256 + tcp_hdr->options[3];

	if ((tcp_hdr->flags & FIN) == FIN)
	{
		printf("\n=============[TCP]成功接收第一次挥手,seq=%d\n", tcp_hdr->sequence);
		tcp_accept1(socketid, 1, 0);

		return 0;
	}
	else
	{
		while (1)
		{
			recvlock4.lock();
			if (RECVBUFFER4.full == false)
			{
				int udpdata_len = buflen - sizeof(tcp_header);
				for (int i = 0; i < udpdata_len; i++)
				{
					RECVBUFFER4.pool[RECVBUFFER4.head][i] = tcp_recv_buffer[i + sizeof(tcp_header) + sizeof(tcp_pseheader)];
					//printf("%c", buf_ptr[i]);
				}
				//printf("\n");
				//printf("-------------receive buffer4---------\n");
				RECVBUFFER4.size_of_packet[RECVBUFFER4.head] = udpdata_len;
				RECVBUFFER4.head = (RECVBUFFER4.head + 1) % NUM_QUE;
				RECVBUFFER4.empty = false;
				if (RECVBUFFER4.head == RECVBUFFER4.tail)
				{
					RECVBUFFER4.full = true;
				}
				recvlock4.unlock();
				tcp_accept1(socketid, udpdata_len, 3);//发送ACK应答
				break;
			}
			recvlock4.unlock();
		}

		recv_tcpdata_index++;
		printf("\n=============[TCP]成功接收第%d个TCP报文,ACK=1,seq=%d,ack=%d\n", recv_tcpdata_index, tcp_hdr->sequence, tcp_hdr->confirmnum);
	}

	return 1;
}

//DWORD WINAPI tcp_recv(LPVOID pM)
//{
// int START = 1;
//	TCPSocket* socketid = tcp_socket();;
//	int LSITEN_RESULT, SYNRECV_RESULT, ESTABLISHED_RESULT, CLOSEWAIT_RESULT, LASTACK_RESULT;
//	while (1)
//	{
//		//使用状态机对服务器端tcp接收进行控制
//		switch (server_recvstate)
//		{
//		case CLOSED:
//			if (START == 1)
//			{
//				tcp_bind(socketid, server_ip, server_port);
//				server_recvstate = LISTEN;
//				START = 0;
//			}
//			break;
//		case LISTEN:
//			recvlock5.lock();
//			if (RECVBUFFER5.empty == false)
//			{
//				LSITEN_RESULT = tcp_listen(socketid, RECVBUFFER5.pool[RECVBUFFER5.tail], RECVBUFFER5.size_of_packet[RECVBUFFER5.tail]);
//				if (LSITEN_RESULT == -1)
//				{
//					printf("[TCP]	USE LISTEN WRONG!!!\n");
//				}
//				else
//				{
//					printf("[TCP]	USE LISTEN SECCESS!!!\n");
//					server_recvstate = SYNRECV;
//					tcp_accept1(socketid, 1, 1);//SYN = 1的报文需要消耗序号
//				}
//				update_thebuffer5();
//			}
//			recvlock5.unlock();
//			break;
//		case SYNRECV:
//			recvlock5.lock();
//			if (RECVBUFFER5.empty == false)
//			{
//				SYNRECV_RESULT = tcp_accept2(socketid, RECVBUFFER5.pool[RECVBUFFER5.tail], RECVBUFFER5.size_of_packet[RECVBUFFER5.tail], 0);
//				if (SYNRECV_RESULT == -1)
//				{
//					printf("[TCP]	USE ACCEPT2 WRONG!!!\n");
//				}
//				else
//				{
//					printf("[TCP]	USE ACCEPT2 SECCESS!!!\n");
//					server_recvstate = ESTABLISHED;
//				}
//				update_thebuffer5();
//			}
//			recvlock5.unlock();
//			break;
//		case ESTABLISHED:
//			recvlock5.lock();
//			if (RECVBUFFER5.empty == false)
//			{
//				ESTABLISHED_RESULT = tcp_recvfrom(socketid, RECVBUFFER5.pool[RECVBUFFER5.tail], RECVBUFFER5.size_of_packet[RECVBUFFER5.tail]);
//				if (ESTABLISHED_RESULT == -1)
//				{
//					printf("[TCP]	RECEIVE THE TCP DATA WRONG!!!\n");
//				}
//				else if (ESTABLISHED_RESULT == 0)
//				{
//					printf("[TCP]	RECEIVE FIRST WAVE AND SEND SECOND WAVE hand\n");
//					server_recvstate = CLOSEWAIT;
//				}
//				else
//				{
//					printf("[TCP]	RECEIVE THE TCP DATA SECCESS!!!\n");
//				}
//				update_thebuffer5();
//			}
//			recvlock5.unlock();
//			break;
//		case CLOSEWAIT:
//			CLOSEWAIT_RESULT = tcp_accept1(socketid, 0, 1);
//			if (CLOSEWAIT_RESULT == -1)
//			{
//				printf("[TCP]	SEND THE TCP THIRD WAVE HAND WRONG!!!\n");
//			}
//			else
//			{
//				printf("[TCP]	SEND THE TCP THIRD WAVE HAND SUCCESS!!!\n");
//				server_recvstate = LASTACK;
//			}
//			break;
//		case LASTACK:
//			recvlock5.lock();
//			if (RECVBUFFER5.empty == false)
//			{
//				LASTACK_RESULT = tcp_accept2(socketid, RECVBUFFER5.pool[RECVBUFFER5.tail], RECVBUFFER5.size_of_packet[RECVBUFFER5.tail], 1);
//				if (LASTACK_RESULT == -1)
//				{
//					printf("[TCP]	第四次挥手失败!!!\n");
//				}
//				else
//				{
//					printf("[TCP]	第四次挥手成功!!!\n");
//					tcp_close(socketid);
//					server_recvstate = CLOSED;
//				}
//				update_thebuffer5();
//			}
//			recvlock5.unlock();
//			break;
//		default:
//			break;
//		}
//	}
//
//	return 0;
//}