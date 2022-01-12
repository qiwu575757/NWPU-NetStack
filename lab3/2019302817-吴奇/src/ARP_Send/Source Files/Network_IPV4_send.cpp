#include "Network_IPV4_send.h"
#include "Resource.h"
#include "Ethernet.h"
#include "ARP_Cache_Table.h"
#include "Network_ARP_send.h"
#include "Network_ARP_recv.h"

//u_int8_t buffer[MAX_SIZE];
u_int16_t ip_packet_id = 0;//as flag in ip_header->id
u_int32_t ip_size_of_packet = 0;
bool end_flag = false;
extern bool arprecv_flag;

extern int ethernet_upper_len;
extern u_int8_t broadcast_mac[6];
extern u_int8_t local_ip[4];
extern u_int8_t target_ip[4];
extern u_int8_t netmask[4];
extern u_int8_t gateway_ip[4];
extern pcap_t *handle;
extern u_int8_t local_mac[6];
extern std::mutex sendlock1;
extern std::mutex sendlock2;
extern sendbuffer1 SENDBUFFER1;
extern sendbuffer2 SENDBUFFER2;

//init the send buffer
void init_sendbuffer1()
{
	SENDBUFFER1.head = 0;
	SENDBUFFER1.tail = 0;
	SENDBUFFER1.full = false;
	SENDBUFFER1.empty = true;
}

void init_sendbuffer2()
{
	SENDBUFFER2.head = 0;
	SENDBUFFER2.tail = 0;
	SENDBUFFER2.full = false;
	SENDBUFFER2.empty = true;
}

u_int16_t calculate_check_sum(ip_header *ip_hdr, int len)
{
	int sum = 0, tmp = len;
	u_int16_t *p = (u_int16_t*)ip_hdr;
	while (len > 1)
	{
		sum += *p;
		len -= 2;
		p++;
	}

	//len=1 last one byte
	if (len)
	{
		sum += *((u_int8_t*)ip_hdr + tmp - 1);
	}

	//fold 32 bits to 16 bits
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

void load_ip_header(u_int8_t *ip_buffer)
{
	struct ip_header *ip_hdr = (struct ip_header*)ip_buffer;
	ip_size_of_packet = 0;
	//initial the ip header
	ip_hdr->version_hdrlen = 0x4f;//0100 1111 means ip version4 and header length: 60 bytes
	ip_hdr->type_of_service = 0xfe;/*111 1 1110: first 3 bits: priority level,
								   then 1 bit: delay, 1 bit: throughput, 1 bit: reliability
								   1 bit: routing cost, 1 bit: unused
								   */
	ip_hdr->total_length = 0;// wait for data length, 0 for now
	ip_hdr->id = ip_packet_id;//identification
	ip_hdr->fragment_offset = 0x0000;/*0 0 0 0 00...00: first 3 bits is flag: 1 bit: 0 the last fragment,
									 1 more fragmet. 1 bit: 0 allow fragment, 1 don't fragment. 1 bit: unused
									 the last 12 bits is offset
									 */
	ip_hdr->time_to_live = 64;//default 1000ms
	ip_hdr->upper_protocol_type = IPPROTO_TCP;//default upper protocol is tcp
	ip_hdr->check_sum = 0;//initial zero

	int i;
	for (i = 0; i < 4; i++)
	{
		ip_hdr->source_ip[i] = local_ip[i];
		ip_hdr->destination_ip[i] = target_ip[i];
	}

	//initial check_sum is associate with offset. so in the data we need to calculate check_sum
	ip_size_of_packet += sizeof(ip_header);
}

void load_ip_data(u_int8_t *ip_buffer, FILE *fp, int len)
{
	int i = 0;
	char ch;
	while (i < len && (ch = fgetc(fp)) != EOF)
	{
		*(ip_buffer + i) = ch;
		i++;
	}
	ip_size_of_packet += len;
}

int is_same_lan(u_int8_t *local_ip, u_int8_t *destination_ip)
{
	int i;
	for (i = 0; i < 4; i++)
	{
		if ((local_ip[i] & netmask[i]) != (destination_ip[i] & netmask[i]))
			return 0;
	}
	return 1;
}

DWORD WINAPI read_from_file(LPVOID pM)
{
	int ip_ethernets = TOTAL_IP_GROUPS;//重复打开同一文件模拟发送多个数据报
	while (ip_ethernets != 0)
	{
		//open file
		FILE* fp;
		fp = fopen("send_data.txt", "rb");
		//get the size of file
		int file_len;
		fseek(fp, 0, SEEK_END);
		file_len = ftell(fp);//file contain data bytes
		rewind(fp);//let the file point reset to the file head

		//get how many fragments
		int number_of_fragment = (int)ceil(file_len * 1.0 / MAX_IP_PACKET_SIZE);
		u_int16_t offset = 0;
		int ip_data_len;
		u_int16_t fragment_offset;
		end_flag = false;
		while ( number_of_fragment != 0 )
		{
			sendlock1.lock();//加锁实现互斥访问
			if (SENDBUFFER1.full == false)
			{
				load_ip_header(SENDBUFFER1.pool[SENDBUFFER1.head]);
				struct ip_header* ip_hdr = (struct ip_header*)SENDBUFFER1.pool[SENDBUFFER1.head];
				if (number_of_fragment == 1)//the last slice
				{
					fragment_offset = 0x0000;//16bits
					ip_data_len = file_len - offset;
				}
				else
				{
					fragment_offset = 0x2000;//allow the next fragment
					ip_data_len = MAX_IP_PACKET_SIZE;
				}

				fragment_offset |= ((offset / 8) & 0x0fff);//get the fragment offset
				ip_hdr->fragment_offset = htons(fragment_offset);
				ip_hdr->total_length = htons(ip_data_len + sizeof(ip_header));
				ip_hdr->check_sum = calculate_check_sum(ip_hdr, 60);

				printf("\n ip data len is %d\n", ip_data_len);
				//加载文件中数据
				load_ip_data(SENDBUFFER1.pool[SENDBUFFER1.head] + sizeof(ip_header), fp, ip_data_len);
				SENDBUFFER1.ip_size_of_packet[SENDBUFFER1.head] = ip_data_len + sizeof(ip_header);

				SENDBUFFER1.head = (SENDBUFFER1.head + 1) % NUM_QUE;
				SENDBUFFER1.empty = false;
			}

			if (SENDBUFFER1.head == SENDBUFFER1.tail)
				SENDBUFFER1.full = true;

			sendlock1.unlock();
			offset += MAX_IP_PACKET_SIZE;
			printf("ip_packet_id is %d,	number of fragment is %d\n", ip_packet_id, number_of_fragment);
			if (number_of_fragment == 1)
			{
				end_flag = true;
			}
			number_of_fragment--;
		}

		//auto increase one
		ip_packet_id++;

		fclose(fp);
		ip_ethernets--;
	}

	return 0;
}

DWORD WINAPI ip_send(LPVOID pM)
{
	while (end_flag == false || SENDBUFFER1.empty == false) {
		//若文件信息还未读完或者发送缓冲区还有数据未发出，需要继续发送
		sendlock1.lock();
		if (SENDBUFFER1.empty == false)
		{
			u_int8_t ip_buffer[MAX_SIZE];
			load_ip_header(ip_buffer);
			struct ip_header* ip_hdr = (struct ip_header*)ip_buffer;

			//get the dest ip
			u_int8_t* dest_ip;
			//check if the target pc and the local host is in the same lan
			if (is_same_lan(local_ip, ip_hdr->destination_ip))
			{
				dest_ip = ip_hdr->destination_ip;
				for (int i = 0; i < 4; i++)
				{
					if (i)printf(".");
					printf("%d", dest_ip[i]);
					dest_ip[i] = ip_hdr->destination_ip[i];
				}
			}
			else
			{
				dest_ip = gateway_ip;
			}

			//send to buffer2
			sendlock2.lock();
			if (SENDBUFFER2.full == false)
			{
				int i;
				u_int8_t* destination_mac = is_existed_ip(dest_ip);
				if (destination_mac == NULL)
				{
					arprecv_flag = true;//标志该进程将循环接收arp响应报文
					network_arp_send(dest_ip, broadcast_mac);//发送arp请求报文

					sendlock2.unlock();
				}

				if ( arprecv_flag )
				{
					destination_mac = datalink_recvarp();//数据链路层获得响应报文
					arprecv_flag = false;

					sendlock2.lock();
				}
				for (i = 0; i < SENDBUFFER1.ip_size_of_packet[SENDBUFFER1.tail]; i++)
				{
					SENDBUFFER2.pool[SENDBUFFER2.head][i] = SENDBUFFER1.pool[SENDBUFFER1.tail][i];
				}
				SENDBUFFER2.ip_size_of_packet[SENDBUFFER2.head] = SENDBUFFER1.ip_size_of_packet[SENDBUFFER1.tail];
				SENDBUFFER2.type[SENDBUFFER2.head] = ETHERNET_IP;
				for (int j = 0; j < 6; j++)
				{
					SENDBUFFER2.destination_mac[SENDBUFFER2.head][j] = *(destination_mac + j);
				}
				SENDBUFFER2.head = (SENDBUFFER2.head + 1) % NUM_QUE;
				SENDBUFFER2.empty = false;
			}
			if (SENDBUFFER2.head == SENDBUFFER2.tail)
				SENDBUFFER2.full = true;
			sendlock2.unlock();

			SENDBUFFER1.tail = (SENDBUFFER1.tail + 1) % NUM_QUE;
			SENDBUFFER1.full = false;
		}
		if (SENDBUFFER1.head == SENDBUFFER1.tail)
			SENDBUFFER1.empty = true;
		sendlock1.unlock();
	}

	return 0;
}