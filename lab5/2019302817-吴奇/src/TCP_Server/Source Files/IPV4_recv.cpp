#include "IPV4_recv.h"
#include "IPV4_send.h"
#include "ws2def.h"
#include "UDP_recv.h"
#include "TCP_recv.h"

extern std::mutex recvlock2;
extern recvbuffer2 RECVBUFFER2;
extern std::mutex sendlock2;
extern sendbuffer2 SENDBUFFER2;
extern u_int32_t crc32_table[256];
extern u_int8_t local_num[2];
extern u_int8_t local_id[2];
extern u_int8_t local_ip[4];
extern bool recv_endflag;

int previous = 0, current = 0;

bool is_accept_icmp()
{
	//收到的数据报的icmp header
	struct icmp_header* icmp_hdr0 = (struct icmp_header*)(RECVBUFFER2.pool[RECVBUFFER2.tail] + sizeof(struct icmp_header));
	//表示如果是ping 回答报文数据部分中包含的之前的icmp header
	struct icmp_header* icmp_hdr1 = (struct icmp_header*)(RECVBUFFER2.pool[RECVBUFFER2.tail] + 2 * sizeof(struct icmp_header) + sizeof(struct icmp_header));
	if (icmp_hdr0->op_code != 0)
		return false;
	if (icmp_hdr0->type_of_service != 0 && icmp_hdr0->type_of_service != 8)
		//just implement th ping request and ping response 
		return false;

	if (icmp_hdr0->type_of_service == 0 && icmp_hdr0->op_code == 0)//icmp response
	{
		if (icmp_hdr1->id != local_id[1] * 256 + local_id[0] || icmp_hdr1->num != local_num[1] * 256 + local_num[0])
			return false;
	}

	//crc match
	u_int16_t crc = calculate_check_sum((ip_header*)(icmp_hdr0), 8);
	if (crc != 0)//检验数据
	{
		printf("The data has changed.\n");
		return false;
	}

	return true;
}

void load_icmp_data(u_int8_t* ip_buffer)
{
	int k = 0;
	SENDBUFFER2.pool[SENDBUFFER2.head][+k++] = 0;//类型字段
	SENDBUFFER2.pool[SENDBUFFER2.head][+k++] = 0;//代码字段
	SENDBUFFER2.pool[SENDBUFFER2.head][+k++] = 0;//初始化检验和字段
	SENDBUFFER2.pool[SENDBUFFER2.head][+k++] = 0;
	SENDBUFFER2.pool[SENDBUFFER2.head][+k++] = local_id[1];
	SENDBUFFER2.pool[SENDBUFFER2.head][+k++] = local_id[0];
	SENDBUFFER2.pool[SENDBUFFER2.head][+k++] = local_num[1];
	SENDBUFFER2.pool[SENDBUFFER2.head][+k++] = local_num[0];
	u_int16_t crc = calculate_check_sum((ip_header*)(SENDBUFFER2.pool[SENDBUFFER2.head]), 8);

	SENDBUFFER2.pool[SENDBUFFER2.head][2] = crc / 256;//检验和字段
	SENDBUFFER2.pool[SENDBUFFER2.head][3] = crc % 256;
	for (; k < 36; k++)
	{
		//将请求报文的ip header 和 icmp header 作为响应报文的icmp数据部分
		SENDBUFFER2.pool[SENDBUFFER2.head][k] = RECVBUFFER2.pool[RECVBUFFER2.tail][k - 8];
	}
}

void icmp_recv()
{
	if (~is_accept_icmp())
		return;

	struct ip_header* ip_hdr = (struct ip_header*)(RECVBUFFER2.pool[RECVBUFFER2.tail] + sizeof(struct ip_header));
	if (ip_hdr->type_of_service == 0)//icmp response
	{
		printf("\n [ICMP]	get the icmp response.");
		//the time from server to client
		struct ip_header* ip_hdr0 = (struct ip_header*)(RECVBUFFER2.pool[RECVBUFFER2.tail]);
		u_int8_t t0 = (64 - ip_hdr0->time_to_live);
		// the time from client to server
		struct ip_header* ip_hdr1 = (struct ip_header*)(RECVBUFFER2.pool[RECVBUFFER2.tail] + 28);
		u_int8_t t1 = (64 - ip_hdr0->time_to_live);

		// get the time by the TTL
		u_int8_t total_ttl = t0 + t1;
		double time = (double)((u_int32_t)(total_ttl) * 2000 / 64.0);//ttl init is 64 means 2000ms 
		printf("\n[ICMP]	the time used is : %f ms.", time);
	}
	else//icmp request
	{
		int ip_data_len;
		sendlock2.lock();//加锁实现互斥访问
		if (SENDBUFFER2.full == false)
		{
			struct icmp_header* icmp_hdr = (struct icmp_header*)SENDBUFFER2.pool[SENDBUFFER2.head];
			//include 8B icmpheader, 20 the request ip header and 8 request icmp header
			ip_data_len = 36;
			icmp_hdr->check_sum = calculate_check_sum((ip_header*)icmp_hdr, 60);
			printf("\n[ICMP]	ip (icmp) data len is %d\n", ip_data_len);

			load_icmp_data(SENDBUFFER2.pool[SENDBUFFER2.head]);
			SENDBUFFER2.size_of_packet[SENDBUFFER2.head] = ip_data_len;
			SENDBUFFER2.proto_type[SENDBUFFER2.head] = IPPROTO_ICMP;
			SENDBUFFER2.head = (SENDBUFFER2.head + 1) % NUM_QUE;
			SENDBUFFER2.empty = false;
		}

		if (SENDBUFFER2.head == SENDBUFFER2.tail)
			SENDBUFFER2.full = true;

		sendlock2.unlock();
	}

}

int is_accept_ip_packet(struct ip_header* ip_hdr)
{
	int i;
	int flag = 0;
	for (i = 0; i < 4; i++)
	{
		if (ip_hdr->destination_ip[i] != local_ip[i])
		{
			printf("[IP]****i = %d, local = %d, dest = %d", i, local_ip[i], ip_hdr->destination_ip[i]);
			break;
		}
	}

	if (i == 4)
	{
		flag = 1;
		printf("[IP]	It's sended to my IP.\n");
	}

	for (i = 0; i < 4; i++)
	{
		if (ip_hdr->destination_ip[i] != 0xff)break;
	}
	if (i == 4)
	{
		flag = 1;
		printf("[IP]	It's broadcast IP.\n");
	}

	if (!flag)
		return 0;

	u_int16_t check_sum = calculate_check_sum(ip_hdr, 60);
	if (check_sum == 0xffff || check_sum == 0x0000)
	{
		printf("[IP]	No error in ip_header.\n");
	}
	else
	{
		printf("[IP]	Error in ip_header\n");
		return 0;
	}
}

void update_thebuffer()
{
	//update the datalink_ip_receivequeue
	if (RECVBUFFER2.full == false)
	{
		RECVBUFFER2.tail = (RECVBUFFER2.tail + 1) % NUM_QUE;
		RECVBUFFER2.full = false;
	}
	if (RECVBUFFER2.head == RECVBUFFER2.tail)
		RECVBUFFER2.empty = true;
}

DWORD WINAPI ipv4_distribute(LPVOID pM)
{
	while (recv_endflag == false || RECVBUFFER2.empty == false)
	{
		recvlock2.lock();
		if (RECVBUFFER2.empty == false)
		{
			//receive the newest ip slice 
			struct ip_header* ip_hdr = (struct ip_header*)RECVBUFFER2.pool[RECVBUFFER2.tail];

			//check the valid
			if (!is_accept_ip_packet(ip_hdr))
			{
				printf("[IP]	is not accept ip packet\n");
				update_thebuffer();
				recvlock2.unlock();//用锁需注意啊，动不动就一个线程多次加锁就导致异常了
				continue;
			}

			//check the time valid
			int dural = 0;
			if (previous == 0)
			{
				previous = time(NULL);
			}
			else
			{
				//get current time
				current = time(NULL);
				dural = current - previous;
				printf("[IP] current = %d, previous = %d\n", current, previous);
				//current time became previous
				previous = current;
			}
			//interval can not larger than 30s，超时重传
			if (dural >= 30)
			{
				printf("[IP]	Time Elapsed.\n");
				update_thebuffer();
				recvlock2.unlock();//用锁需注意啊，动不动就一个线程多次锁定导致异常了
				continue;
			}

			switch (ip_hdr->upper_protocol_type)
			{
			case IPPROTO_TCP:
				tcp_readfrom_ip();
				break;
			case IPPROTO_UDP:
				udp_recv();
				break;
			case IPPROTO_ICMP:
				icmp_recv();
				break;
			default:
				break;
			}

			update_thebuffer();
		}
		recvlock2.unlock();
	}

	return 0;
}