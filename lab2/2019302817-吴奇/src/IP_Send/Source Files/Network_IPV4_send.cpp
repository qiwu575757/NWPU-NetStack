#include "Network_IPV4_send.h"

u_int16_t ip_packet_id = 0;//as flag in ip_header->id
bool end_flag = false;
std::mutex mylock;

//send buffer
struct ip_send_buffer {
	int head;
	int tail;
	u_int8_t pool[NUM_QUE][1600];
	u_int32_t ip_size_of_packet[NUM_QUE];
	bool full;
	bool empty;
}IP_SEND_BUFFER;

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

	//initial the ip header
	ip_hdr->version_hdrlen = 0x4f; //ipv4, 60B
	ip_hdr->type_of_service = 0xfe;//low delay, high throughput, high reliablity,
	ip_hdr->total_length = 0;// wait for data length, 0 for now
	ip_hdr->id = ip_packet_id;//identification

	ip_hdr->fragment_offset = 0x0000;// 0 DF MF FRAGMENT_OFFSET
	ip_hdr->time_to_live = 64;//default 1000ms
	ip_hdr->upper_protocol_type = IPPROTO_TCP;//default upper protocol is tcp
	ip_hdr->check_sum = 0;//initial zero
	ip_hdr->source_ip.s_addr = inet_addr("10.13.80.43");//convert ip string to a unsigned long 
	ip_hdr->destination_ip.s_addr = inet_addr("255.255.255.255");
	//initial check_sum is associate with offset. so in the data we need to calculate check_sum
}

void load_ip_data(u_int8_t *ip_buffer, FILE *fp, int len)
{
	int i = 0;//开始未初始化造成只有一般内容进行复制的奇怪现象，太离谱了
	char ch;
	while (i < len && (ch = fgetc(fp)) != EOF)
	{
		*(ip_buffer + i) = ch;
		i++;
	}
}

//init the send buffer
void init_sendbuffer()
{
	IP_SEND_BUFFER.head = 0;
	IP_SEND_BUFFER.tail = 0;
	IP_SEND_BUFFER.full = false;
	IP_SEND_BUFFER.empty = true;
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
			mylock.lock();//加锁实现互斥访问
			if (IP_SEND_BUFFER.full == false)
			{
				load_ip_header(IP_SEND_BUFFER.pool[IP_SEND_BUFFER.head]);
				struct ip_header* ip_hdr = (struct ip_header*)IP_SEND_BUFFER.pool[IP_SEND_BUFFER.head];
				if ( number_of_fragment == 1 )//the last slice
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
				load_ip_data(IP_SEND_BUFFER.pool[IP_SEND_BUFFER.head] + sizeof(ip_header), fp, ip_data_len);
				IP_SEND_BUFFER.ip_size_of_packet[IP_SEND_BUFFER.head] = ip_data_len + sizeof(ip_header);

				IP_SEND_BUFFER.head = (IP_SEND_BUFFER.head + 1) % NUM_QUE;
				IP_SEND_BUFFER.empty = false;
			}

			if (IP_SEND_BUFFER.head == IP_SEND_BUFFER.tail)
				IP_SEND_BUFFER.full = true;

			mylock.unlock();
			offset += MAX_IP_PACKET_SIZE;
			printf("ip_packet_id is %d,number of fragment is %d\n", ip_packet_id,number_of_fragment);
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
	while (end_flag == false || IP_SEND_BUFFER.empty == false) {
		//若文件信息还未读完或者发送缓冲区还有数据未发出，需要继续发送
		mylock.lock();
		if (IP_SEND_BUFFER.empty == false)
		{
			datalink_send(IP_SEND_BUFFER.pool[IP_SEND_BUFFER.tail], IP_SEND_BUFFER.ip_size_of_packet[IP_SEND_BUFFER.tail]);
			IP_SEND_BUFFER.tail = (IP_SEND_BUFFER.tail + 1) % NUM_QUE;
			IP_SEND_BUFFER.full = false;
		}
		if (IP_SEND_BUFFER.head == IP_SEND_BUFFER.tail)
			IP_SEND_BUFFER.empty = true;
		mylock.unlock();
	}

	return 0;
}




