#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

#define BUFFER_SIZE 1024

void get_ip(int sock, int *ip);
void *create_shared_memory(size_t num_bytes);
int destroy_shared_memory(void *shm, size_t size);
int get_file_permissions(char *file, char permissions[10]);
#endif // UTILS_H