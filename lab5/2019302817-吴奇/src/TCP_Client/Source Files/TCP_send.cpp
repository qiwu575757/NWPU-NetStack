#include "TCP_send.h"
#include "IPV4_send.h"
#include "TCP.h"
#include "TCP_recv.h"
#include "UDP_recv.h"

extern int client_sendstate;
extern int	host;
extern bool send_endflag;
extern TCB* tcb;
extern std::mutex sendlock2;
extern std::mutex sendlock3;
extern std::mutex recvlock5;
extern sendbuffer2 SENDBUFFER2;
extern sendbuffer3 SENDBUFFER3;
extern recvbuffer5 RECVBUFFER5;
extern u_int16_t server_port;
extern u_int8_t target_ip[4];
extern u_int8_t server_ip[4];
extern u_int8_t local_ip[4];

u_int8_t tcp_send_buffer[1600] = { 0 };
u_int8_t tcp_buffer[1600] = { 0 };
u_int8_t temp_data_buffer[16020] = { 0 };
int START = 1;
int send_messages = 0;
int recv_messages = 0;

//用于发送第一次、第三次握手，第一次、第四次挥手
int tcp_connect1(TCPSocket* socketid, int send_type)
{
	int i,k;
	if (host != CLIENT)
		return -1;

	//第一次握手时对tcp control block进行分配
	if (send_type == 1)
	{
		//动态更新通信五元组信息
		for (i = 0; i < 4; i++)
			socketid->target_ip[i] = server_ip[i];
		socketid->target_port = server_port;
		srand((unsigned)time(NULL));
		tcb = (TCB*)malloc(sizeof(TCB));
		tcb->client_initial_seq = 10000 * (rand() % 50);
		tcb->client_mss = MSS;
		tcb->recv_window_size = 1;
		tcb->recv_cache_size = NUM_QUE;
		tcb->send_window_size = 1;
		tcb->send_cache_size = NUM_QUE;
	}

	tcp_header* tcp_hdr = (tcp_header*)(tcp_send_buffer + sizeof(tcp_pseheader));
	tcp_pseheader* tcp_psehdr = (tcp_pseheader*)tcp_send_buffer;
	u_int8_t* buf = tcp_send_buffer + sizeof(tcp_pseheader) + sizeof(tcp_header);

	//tcp pseheader init
	for (k = 0; k < 4; k++)
	{
		tcp_psehdr->dest_ip[k] = target_ip[k];
		tcp_psehdr->src_ip[k] = local_ip[k];
	}
	tcp_psehdr->length = sizeof(tcp_header);//响应报文数据部分为空
	tcp_psehdr->protocol = 6;
	tcp_psehdr->reserve = 0;

	//tcp header init
	tcp_hdr->src_port = socketid->local_port;
	tcp_hdr->dest_port = socketid->target_port;
	tcp_hdr->sequence = tcb->client_initial_seq;
	tcp_hdr->confirmnum = tcb->server_initial_seq + 1;
	tcp_hdr->header_length = (sizeof(tcp_header) / 4) << 4;
	if (send_type == 1)
		tcp_hdr->flags = SYN;
	else if (send_type == 2)
		tcp_hdr->flags = FIN;
	else//第三次握手或第四次挥手
		tcp_hdr->flags = ACK;

	tcp_hdr->window = tcb->recv_window_size;
	tcp_hdr->checknum = 0;
	tcp_hdr->urgent_pointer = 0;
	tcp_hdr->options[0] = 2;	//填写MSS选项字段
	tcp_hdr->options[1] = 4;
	tcp_hdr->options[2] = tcb->client_mss / 256;
	tcp_hdr->options[3] = tcb->client_mss % 256;

	tcp_hdr->checknum = calculate_check_sum((ip_header*)tcp_send_buffer, tcp_psehdr->length + sizeof(tcp_psehdr));
	//send first handmake
	bool end = false;
	while (end == false)
	{
		sendlock2.lock();
		if (SENDBUFFER2.full == false)
		{
			SENDBUFFER2.size_of_packet[SENDBUFFER2.head] = tcp_psehdr->length;
			for (k = 0; k < SENDBUFFER2.size_of_packet[SENDBUFFER2.head]; k++)
			{
				SENDBUFFER2.pool[SENDBUFFER2.head][k] = tcp_send_buffer[k + sizeof(tcp_pseheader)];
			}
			SENDBUFFER2.proto_type[SENDBUFFER2.head] = IPPROTO_TCP;
			SENDBUFFER2.head = (SENDBUFFER2.head + 1) % NUM_QUE;
			SENDBUFFER2.empty = false;
			if (SENDBUFFER2.head == SENDBUFFER2.tail)
				SENDBUFFER2.full = true;
			if (send_type == 1)
				printf("\n[TCP]成功发送第一次握手,SYN = 1,seq=%d\n", tcp_hdr->sequence);
			else if (send_type == 2)
				printf("\n[TCP]成功发送第一次挥手,FIN = 1,seq=%d\n", tcp_hdr->sequence);
			else if (send_type == 3)
			{
				printf("\n[TCP]成功发送第四次挥手,ACK = 1,seq=%d,ack=%d\n", tcp_hdr->sequence, tcp_hdr->confirmnum);
			}
			else if (send_type == 4)
			{
				printf("\n[TCP]成功发送第三次握手,ACK = 1,seq=%d,ack=%d\n", tcp_hdr->sequence, tcp_hdr->confirmnum);
			}
			end = true;
		}

		sendlock2.unlock();
	}

	return 1;
}

//用于接收第二次握手、第二次、第三次挥手和数据接收确认响应
int tcp_connect2(TCPSocket* socketid, u_int8_t* buf, int buflen, int recvtype)
{
	int k;
	//load tcp data to [pseheader+tcpdata] buffer
	load_data_to_buffer(tcp_send_buffer + sizeof(tcp_pseheader), buf, buflen);
	if (host != CLIENT)
		return -1;

	tcp_header* tcp_hdr = (tcp_header*)(tcp_send_buffer + sizeof(tcp_pseheader));
	tcp_pseheader* tcp_psehdr = (tcp_pseheader*)tcp_send_buffer;

	//tcp pseheader init
	for (k = 0; k < 4; k++)
	{
		tcp_psehdr->dest_ip[k] = local_ip[k];
		tcp_psehdr->src_ip[k] = target_ip[k];
	}
	tcp_psehdr->length = buflen;
	tcp_psehdr->protocol = 6;
	tcp_psehdr->reserve = 0;

	if (tcp_hdr->flags != (SYN + ACK) && recvtype == 0)
	{
		printf("[TCP]接收第二次握手标志位错误\n");
		return -1;
	}
	else if ((tcp_hdr->flags  != (FIN + ACK)) && recvtype == 1)
	{
		printf("[TCP]接收第三次挥手标志位错误\n");
		return -1;
	}
	else if ((tcp_hdr->flags != ACK) && recvtype == 2)
	{
		printf("[TCP]接收第二次挥手标志位错误\n");
		return -1;
	}
	else if ((tcp_hdr->flags  != ACK) && recvtype == 3)
	{
		printf("[TCP]接收数据传送响应标志位错误\n");
		return -1;
	}

	if ((tcp_hdr->dest_port) != socketid->local_port) {
		printf("[TCP]Wrong Destination Port! %d-%d\n", tcp_hdr->dest_port, socketid->local_port);
		return -1;
	}
	u_int16_t checknum = calculate_check_sum((ip_header*)tcp_send_buffer, buflen + sizeof(tcp_psehdr));
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
	tcb->server_initial_seq = tcp_hdr->sequence;
	tcb->server_mss = tcp_hdr->options[2] * 256 + tcp_hdr->options[3];
	tcb->client_initial_seq = tcp_hdr->confirmnum;

	if (recvtype == 0)//接收第二次握手
	{
		printf("\n=============[TCP]成功接收第二次握手,SYN = 1,ACK = 1,seq=%d,ack=%d\n",tcp_hdr->sequence,tcp_hdr->confirmnum);
	}
	else if (recvtype == 1)//接收第二次挥手
	{
		printf("\n=============[TCP]成功接收第三次挥手,ACK = 1,seq=%d,ack=%d\n", tcp_hdr->sequence, tcp_hdr->confirmnum);
	}
	else if (recvtype == 2)//接收第三次挥手
	{
		printf("\n=============[TCP]成功接收第二次挥手,FIN = 1,ACK = 1,seq=%d,ack=%d\n", tcp_hdr->sequence, tcp_hdr->confirmnum);
	}
	else
	{
		recv_messages++;
		printf("\n=============[TCP]成功接收第%d次数据传输的响应报文,ACK = 1,seq=%d,ack=%d\n", recv_messages,tcp_hdr->sequence, tcp_hdr->confirmnum);
	}

	return 1;
}

int tcp_sendto(TCPSocket* socketid, u_int8_t* buf, int have_send_messages, int buflen)
{
	tcp_header* tcp_hdr = (tcp_header*)(tcp_buffer + sizeof(tcp_pseheader));
	tcp_pseheader* tcp_psehdr = (tcp_pseheader*)(tcp_buffer);
	u_int8_t* tcp_databuf = tcp_buffer + sizeof(tcp_pseheader) + sizeof(tcp_header);
	int i, k;
	
	//tcp pseheader init
	for (k = 0; k < 4; k++)
	{
		tcp_psehdr->dest_ip[k] = target_ip[k];
		tcp_psehdr->src_ip[k] = local_ip[k];
	}
	tcp_psehdr->length = sizeof(tcp_header)+ buflen;//数据传送报文
	tcp_psehdr->protocol = 6;
	tcp_psehdr->reserve = 0;

	//tcp header init
	tcp_hdr->src_port = socketid->local_port;
	tcp_hdr->dest_port = socketid->target_port;
	tcp_hdr->sequence = tcb->client_initial_seq;
	tcp_hdr->confirmnum = tcb->server_initial_seq + 1;
	tcp_hdr->header_length = (sizeof(tcp_header) / 4) << 4;
	tcp_hdr->flags = ACK;

	tcp_hdr->window = tcb->recv_window_size;
	tcp_hdr->checknum = 0;
	tcp_hdr->urgent_pointer = 0;
	tcp_hdr->options[0] = 2;	//填写MSS选项字段
	tcp_hdr->options[1] = 4;
	tcp_hdr->options[2] = tcb->client_mss / 256;
	tcp_hdr->options[3] = tcb->client_mss % 256;
	for (i = 0; i < buflen; i++)
	{
		tcp_databuf[i] = buf[i + MSS * have_send_messages];
	}
	tcp_hdr->checknum = calculate_check_sum((ip_header*)tcp_buffer, tcp_psehdr->length + sizeof(tcp_psehdr));
	
	//redict the data to the sendbuffer2
	SENDBUFFER2.size_of_packet[SENDBUFFER2.head] = buflen + sizeof(tcp_header);
	for (i = 0; i < SENDBUFFER2.size_of_packet[SENDBUFFER2.head]; i++)
	{
		SENDBUFFER2.pool[SENDBUFFER2.head][i] = tcp_buffer[i + sizeof(tcp_pseheader)];
	}

	SENDBUFFER2.proto_type[SENDBUFFER2.head] = IPPROTO_TCP;
	SENDBUFFER2.head = (SENDBUFFER2.head + 1) % NUM_QUE;
	SENDBUFFER2.empty = false;
	printf("[TCP]成功发送第%d个数据传送报文\n",++send_messages);

	return 1;
}

DWORD WINAPI tcp_send(LPVOID pM)
{
	TCPSocket* socketid = tcp_socket();
	int CLOSED_RESULT, SYNSENT_RESULT, ESTABLISHED_RESULT, FINWAIT1_RESULT, FINWAIT2_RESULT, TIMEWAIT_RESULT;
	int datalen = 0, have_send_messages=0;
	bool is_send = false;
	while (1) {
	//若文件信息还未读完或者发送缓冲区还有数据未发出，需要继续发送
		switch (client_sendstate)
		{
			case CLOSED:
				if (START == 1)
				{
					CLOSED_RESULT = tcp_connect1(socketid,1);
					if (CLOSED_RESULT == -1)
					{
						printf("[TCP]	USE CONNECT1 WRONG!!!\n");
					}
					else
					{
						printf("[TCP]	USE CONNECT1 SECCESS!!!\n");
						client_sendstate = SYNSENT;
						START = 0;
					}
				}
				break;
			case SYNSENT:
				recvlock5.lock();
				if (RECVBUFFER5.empty == false)
				{
					//接收第二次握手
					SYNSENT_RESULT = tcp_connect2(socketid, RECVBUFFER5.pool[RECVBUFFER5.tail], RECVBUFFER5.size_of_packet[RECVBUFFER5.tail],0);
					if (SYNSENT_RESULT == -1)
					{
						printf("[TCP]	USE CONNECT2 WRONG!!!\n");
					}
					else
					{
						printf("[TCP]	USE CONNECT2 SECCESS!!!\n");
						tcp_connect1(socketid, 4);
						client_sendstate = ESTABLISHED;
					}
					update_thebuffer5();
				}
				recvlock5.unlock();
				break;
			case ESTABLISHED:
				while (send_endflag == false || SENDBUFFER3.empty == false) {
					//若文件信息还未读完或者发送缓冲区还有数据未发出，需要继续发送
					sendlock3.lock();
					//get how many fragments
					int number_of_message = (int)ceil(SENDBUFFER3.size_of_packet[SENDBUFFER3.tail] * 1.0 / MSS);
					load_data_to_buffer(temp_data_buffer, SENDBUFFER3.pool[SENDBUFFER3.tail], SENDBUFFER3.size_of_packet[SENDBUFFER3.tail]);
					datalen = SENDBUFFER3.size_of_packet[SENDBUFFER3.tail];
					
					if (SENDBUFFER3.empty == false)
					{
						while (number_of_message != 0)
						{
							//send to buffer2
							sendlock2.lock();
							if (SENDBUFFER2.full == false)
							{
								if (number_of_message == 1)
								{
									ESTABLISHED_RESULT = tcp_sendto(socketid, temp_data_buffer, have_send_messages, datalen%MSS);
								}
								else
								{
									ESTABLISHED_RESULT = tcp_sendto(socketid, temp_data_buffer, have_send_messages, MSS);
								}

								if (ESTABLISHED_RESULT == 0)
								{
									printf("[TCP]	SEND DATA WRONG!!!\n");
								}
								is_send = true;
								number_of_message--;
								have_send_messages++;
							}
							if (SENDBUFFER2.head == SENDBUFFER2.tail)
								SENDBUFFER2.full = true;
							sendlock2.unlock();
							if (is_send)
							{
								bool end = false;
								while (end == false)
								{
									recvlock5.lock();
									if (RECVBUFFER5.empty == false)
									{
										tcp_connect2(socketid, RECVBUFFER5.pool[RECVBUFFER5.tail], RECVBUFFER5.size_of_packet[RECVBUFFER5.tail], 3);
										update_thebuffer5();
										is_send = false;
										end = true;
									}
									recvlock5.unlock();
								}
							}
						}

						SENDBUFFER3.tail = (SENDBUFFER3.tail + 1) % NUM_QUE;
						SENDBUFFER3.full = false;
					}
					if (SENDBUFFER3.head == SENDBUFFER3.tail)
						SENDBUFFER3.empty = true;
					sendlock3.unlock();
				}
				tcp_connect1(socketid, 2);//发出第一次挥手
				client_sendstate = FINWAIT1;
				break;
			case FINWAIT1:
				recvlock5.lock();
				if (RECVBUFFER5.empty == false)
				{
					//接收第二次挥手
					FINWAIT1_RESULT = tcp_connect2(socketid, RECVBUFFER5.pool[RECVBUFFER5.tail], RECVBUFFER5.size_of_packet[RECVBUFFER5.tail], 2);
					if (FINWAIT1_RESULT == -1)
					{
						printf("[TCP]	USE CONNECT2 WRONG!!!\n");
					}
					else
					{
						printf("[TCP]	USE CONNECT2 SECCESS!!!\n");
						client_sendstate = FINWAIT2;
					}
					update_thebuffer5();
				}
				recvlock5.unlock();
				break;
			case FINWAIT2:
				recvlock5.lock();
				if (RECVBUFFER5.empty == false)
				{
					//接收第三次挥手
					FINWAIT2_RESULT = tcp_connect2(socketid, RECVBUFFER5.pool[RECVBUFFER5.tail], RECVBUFFER5.size_of_packet[RECVBUFFER5.tail], 1);
					if (FINWAIT2_RESULT == -1)
					{
						printf("[TCP]	USE CONNECT2 WRONG!!!\n");
					}
					else
					{
						printf("[TCP]	USE CONNECT2 SECCESS!!!\n");
						tcp_connect1(socketid, 3);//发送第四次挥手
						client_sendstate = TIMEWAIT;
					}
					update_thebuffer5();
				}
				recvlock5.unlock();
				break;
			case TIMEWAIT:
				client_sendstate = CLOSED;
				break;
			default:
				break;
		}
	}

	return 0;
}
