#include "UDP_recv.h"
#include "IPV4_send.h"

extern bool recv_endflag;
extern std::mutex recvlock2;
extern std::mutex recvlock4;
extern recvbuffer2 RECVBUFFER2;
extern recvbuffer4 RECVBUFFER4;
extern u_int16_t local_port;
extern u_int8_t local_ip[4];

int total_receive = 0;
u_int16_t ip_id = 0;
u_int16_t total_len = 0;//记录整个ip数据报的长度
u_int8_t udp_buffer[16020];//变量命名需注意啊
u_int8_t udp_recv_buffer[16032] = { 0 };

void load_data_to_buffer(u_int8_t* target_buffer, u_int8_t* src_data, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
	{
		*(target_buffer + i) = *(src_data + i);
	}
}

int udp_recvfrom(UDPSocket* socketid, u_int8_t* buf, int buflen, u_int8_t* source_ip, u_int16_t source_port)
{
	//load udp data to [pseheader+udpdata] buffer
	load_data_to_buffer(udp_recv_buffer + sizeof(udp_pseheader), buf, buflen);
	udp_header* udp_hdr = (udp_header*)(udp_recv_buffer + sizeof(udp_pseheader));
	udp_pseheader* udp_psehdr = (udp_pseheader*)udp_recv_buffer;
	u_int8_t* buf_ptr = udp_recv_buffer + sizeof(udp_pseheader) + sizeof(udp_header);
	int i, len;
	u_int16_t checksum;
	
	//本次测试中只有一个客户端、一个服务器端
	//load udp pseheader
	for (i = 0; i < 4; i++)
		udp_psehdr->src_ip[i] = socketid->target_ip[i];
	for (i = 0; i < 4; i++)
		udp_psehdr->dest_ip[i] = source_ip[i];
	udp_psehdr->length = udp_hdr->length;
	udp_psehdr->protocol = 17;
	udp_psehdr->reserve = 0;
	
	if (udp_hdr->dest_port != socketid->local_port )
	{
		printf("[UDP]Wrong dest port!\n");
		return -1;
	}
	int udpdata_len = buflen - sizeof(udp_header);
	//calculate the checknum
	if (udpdata_len % 2 == 0)
	{
		checksum = calculate_check_sum((ip_header*)udp_recv_buffer, buflen + sizeof(udp_psehdr));
	}
	else//若udp数据部分为奇数字节需要填充0来计算检验和
	{
		buf_ptr[udpdata_len] = 0;
		checksum = calculate_check_sum((ip_header*)udp_recv_buffer, buflen + sizeof(udp_psehdr)+1);
	}
	if (checksum != 0xffff)
	{
		printf("[UDP]Wrong Checksum!\n");
		return -1;
	}

	for (i = 0; i < udpdata_len; i++)
	{
		RECVBUFFER4.pool[RECVBUFFER4.head][i] = buf_ptr[i];
	}
	RECVBUFFER4.size_of_packet[RECVBUFFER4.head] = udpdata_len;
	RECVBUFFER4.head = (RECVBUFFER4.head + 1) % NUM_QUE;
	RECVBUFFER4.empty = false;

	return udpdata_len;
}

void udp_recv()
{
	//receive the newest ip slice 
	struct ip_header* ip_hdr = (struct ip_header*)RECVBUFFER2.pool[RECVBUFFER2.tail];

	u_int16_t fragment;
	fragment = ntohs(ip_hdr->fragment_offset);
	int len = ntohs(ip_hdr->total_length) - sizeof(ip_header);
	if ((fragment & 0x2000) && (ip_id == ip_hdr->id))//true means more fragment
	{
		printf("\n1.0 len = %d, totallen = %d\n", len, total_len + len);
		load_data_to_buffer(udp_buffer + total_len, RECVBUFFER2.pool[RECVBUFFER2.tail] + sizeof(ip_header), len);
		total_len += len;
	}
	else
	{
		recvlock4.lock();
		if (RECVBUFFER4.full == false)
		{
			printf("\n2.0 len = %d, totallen = %d\n", len, total_len + len);
			load_data_to_buffer(udp_buffer + total_len, RECVBUFFER2.pool[RECVBUFFER2.tail] + sizeof(ip_header), len);
			printf("\n3.0 len = %d, totallen = %d\n", len, total_len + len);
			total_len += len;

			UDPSocket* socketid = udp_socket();
			int recvfrom_result = udp_recvfrom(socketid, udp_buffer, total_len, local_ip, local_port);
			if (recvfrom_result == -1)
			{
				printf("\nsend to error!!!\n");
			}

			udp_close(socketid);
			total_len = 0;
		}
		if (RECVBUFFER4.head == RECVBUFFER4.tail)
			RECVBUFFER4.full = true;
		recvlock4.unlock();

		if (total_receive == TOTAL_GROUPS)//若到了第5个ip分组的最后，将结束标志置为 true
		{
			recv_endflag = true;
		}
		ip_id++;
		total_receive++;
	}
}