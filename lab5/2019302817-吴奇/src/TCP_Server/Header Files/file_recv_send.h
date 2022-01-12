#include "Resource.h"

//DWORD WINAPI read_from_file(LPVOID pM);
void load_file_data(u_int8_t* buffer, FILE* fp, int length);
DWORD WINAPI write_to_file(LPVOID pM);
int load_data_to_file(u_int8_t* data_buffer, int len, FILE* fp);
