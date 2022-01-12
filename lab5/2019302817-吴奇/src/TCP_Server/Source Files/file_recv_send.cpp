#include "file_recv_send.h"

extern bool send_endflag;
extern bool recv_endflag;
extern std::mutex sendlock3;
extern sendbuffer3 SENDBUFFER3;
extern std::mutex recvlock4;
extern recvbuffer4 RECVBUFFER4;

void load_file_data(u_int8_t* buffer, FILE* fp, int length)
{
	int i = 0;
	char ch;
	while (i < length && (ch = fgetc(fp)) != EOF)
	{
		*(buffer + i) = ch;
		i++;
		//show the data for debug;
		//printf("%c", ch);
	}
	//printf("\n*********************\n");
	return;
}

int load_data_to_file(u_int8_t* data_buffer, int len, FILE* fp)
{
	int res = fwrite(data_buffer, sizeof(u_int8_t), len, fp);
	if (res != len)
	{
		printf("[FILE]	Write file error!\n");
		return 0;
	}
	fflush(fp);
	return 1;
}

//DWORD WINAPI read_from_file(LPVOID pM)
//{
//	int total_senders = TOTAL_GROUPS;//重复打开同一文件模拟发送多个数据报
//	printf("----------------------FILE SEND---------------------------\n");
//	while (total_senders != 0)
//	{
//		//open file
//		FILE* fp;
//		fp = fopen("server_send_data.txt", "rb");
//		//get the size of file
//		int file_len;
//		fseek(fp, 0, SEEK_END);
//		file_len = ftell(fp);//file contain data bytes
//		rewind(fp);//let the file point reset to the file head
//
//		sendlock3.lock();//加锁实现互斥访问
//		if (SENDBUFFER3.full == false)
//		{
//			load_file_data(SENDBUFFER3.pool[SENDBUFFER3.head], fp, file_len);
//			SENDBUFFER3.size_of_packet[SENDBUFFER3.head] = file_len;
//
//			SENDBUFFER3.head = (SENDBUFFER3.head + 1) % NUM_QUE;
//			SENDBUFFER3.empty = false;
//		}
//
//		if (SENDBUFFER3.head == SENDBUFFER3.tail)
//			SENDBUFFER3.full = true;
//		sendlock3.unlock();
//
//		fclose(fp);
//		total_senders--;
//	}
//	send_endflag = true;
//	printf("----------------------END OF FILE SEND---------------------------\n");
//
//	return 0;
//}

DWORD WINAPI write_to_file(LPVOID pM)
{
	printf("----------------------FILE RECEIVE---------------------------\n");
	while (1)
	{
		/*if (recv_endflag == false )
			printf("\n**********************write to file1***************\n");*/
		recvlock4.lock();
		if (RECVBUFFER4.empty == false)
		{
			FILE* fp = fopen("server_recv_data.txt", "a+");
			if (load_data_to_file(RECVBUFFER4.pool[RECVBUFFER4.tail], RECVBUFFER4.size_of_packet[RECVBUFFER4.tail], fp))
			{
				printf("\n**********************write to file***************\n");
				printf("[FILE]	Load to file Succeed.\n");
			}
			RECVBUFFER4.tail = (RECVBUFFER4.tail + 1) % NUM_QUE;
			RECVBUFFER4.full = false;
			fclose(fp);
		}
		if (RECVBUFFER4.head == RECVBUFFER4.tail)
		{
			RECVBUFFER4.empty = true;
		}
		recvlock4.unlock();
	}

	printf("----------------------END OF FILE RECEIVE---------------------------\n");


	return 0;
}