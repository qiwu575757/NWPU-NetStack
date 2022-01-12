#include "UDP_send.h"
#include "IPV4_send.h"

extern bool send_endflag;
extern std::mutex sendlock2;
extern std::mutex sendlock3;
extern sendbuffer2 SENDBUFFER2;
extern sendbuffer3 SENDBUFFER3;
extern u_int16_t server_port;
extern u_int8_t target_ip[4];

u_int8_t udp_send_buffer[16020] = { 0 };

int udp_sendto(UDPSocket* socketid, u_int8_t* buf, int buflen, u_int8_t* dest_ip, u_int16_t dest_port)
{
	udp_header* udp_hdr = (udp_header*)(udp_send_buffer + sizeof(udp_pseheader));
	udp_pseheader* udp_psehdr = (udp_pseheader*)(udp_send_buffer);
	u_int8_t* udp_databuf = udp_send_buffer + sizeof(udp_pseheader) + sizeof(udp_header);

	//load udp header
	udp_hdr->src_port = socketid->local_port;
	udp_hdr->dest_port = dest_port;
	udp_hdr->length = buflen + sizeof(udp_header);
	udp_hdr->checknum = 0;//先初始化为0，之后重新计算
	//load udp pseheader
	int i;
	for (i = 0; i < 4; i++)
		udp_psehdr->src_ip[i] = socketid->local_ip[i];
	for (i = 0; i < 4; i++)
		udp_psehdr->dest_ip[i] = dest_ip[i];
	udp_psehdr->length = udp_hdr->length;
	udp_psehdr->protocol = 17;
	udp_psehdr->reserve = 0;
	//load udp data
	for (i = 0; i < buflen; i++)
		udp_databuf[i] = buf[i];
	if (buflen % 2 != 0)//若udp数据部分为奇数字节需要填充0来计算检验和
	{
		udp_databuf[i] = 0;
		//recalculate the checknun
		udp_hdr->checknum = calculate_check_sum((ip_header*)udp_send_buffer, sizeof(udp_psehdr) + sizeof(udp_header) + buflen + 1);
	}
	else
	{
		//recalculate the checknun
		udp_hdr->checknum = calculate_check_sum((ip_header*)udp_send_buffer, sizeof(udp_psehdr) + sizeof(udp_header) + buflen);
	}

	//redict the data to the sendbuffer2
	SENDBUFFER2.size_of_packet[SENDBUFFER2.head] = buflen + sizeof(udp_header);
	for (i = 0; i < SENDBUFFER2.size_of_packet[SENDBUFFER2.head]; i++)
	{
		SENDBUFFER2.pool[SENDBUFFER2.head][i] = udp_send_buffer[i + sizeof(udp_pseheader)];
	}
	SENDBUFFER2.proto_type[SENDBUFFER2.head] = IPPROTO_UDP;
	SENDBUFFER2.head = (SENDBUFFER2.head + 1) % NUM_QUE;
	SENDBUFFER2.empty = false;

	return SENDBUFFER2.size_of_packet[SENDBUFFER2.head];
}

DWORD WINAPI udp_send(LPVOID pM)
{
	while (send_endflag == false || SENDBUFFER3.empty == false) {
		//若文件信息还未读完或者发送缓冲区还有数据未发出，需要继续发送
		sendlock3.lock();
		if (SENDBUFFER3.empty == false)
		{
			UDPSocket* socketid = udp_socket();

			//用来作为pseheader+udpheader+data的缓冲区
			//send to buffer2
			sendlock2.lock();
			if (SENDBUFFER2.full == false)
			{
				int sendto_result = udp_sendto(socketid, SENDBUFFER3.pool[SENDBUFFER3.tail], SENDBUFFER3.size_of_packet[SENDBUFFER3.tail], target_ip, server_port);

				if (sendto_result == 0)
				{
					printf("\nsend to error!!!\n");
				}
			}
			if (SENDBUFFER2.head == SENDBUFFER2.tail)
				SENDBUFFER2.full = true;
			udp_close(socketid);

			sendlock2.unlock();

			SENDBUFFER3.tail = (SENDBUFFER3.tail + 1) % NUM_QUE;
			SENDBUFFER3.full = false;
		}
		if (SENDBUFFER3.head == SENDBUFFER3.tail)
			SENDBUFFER3.empty = true;
		sendlock3.unlock();
	}

	return 0;
}
