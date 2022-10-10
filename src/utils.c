#include "utils.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>

void get_ip(int sock, int *ip)
{
    socklen_t addr_size = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    getsockname(sock, (struct sockaddr *)&addr, &addr_size);

    char *host = inet_ntoa(addr.sin_addr);
    sscanf(host, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
}

void *create_shared_memory(size_t num_bytes)
{ // Our memory buffer will be readable and writable:
    int protection = PROT_READ | PROT_WRITE;

    // The buffer will be shared (meaning other processes can access it), but
    // anonymous (meaning third-party processes cannot obtain an address for it),
    // so only this process and its children will be able to use it:
    int visibility = MAP_SHARED | MAP_ANONYMOUS;

    // The remaining parameters to `mmap()` are not important for this use case,
    return mmap(NULL, num_bytes, protection, visibility, -1, 0);
}

int destroy_shared_memory(void *shm, size_t size)
{ // Our memory buffer will be readable and writable:
    return munmap(shm, sizeof *shm);
}

int get_file_permissions(char *file, char permissions[10])
{
    struct stat st;
    if (stat(file, &st) == 0)
    {
        mode_t perm = st.st_mode;
        permissions[0] = (perm & S_IRUSR) ? 'r' : '-';
        permissions[1] = (perm & S_IWUSR) ? 'w' : '-';
        permissions[2] = (perm & S_IXUSR) ? 'x' : '-';
        permissions[3] = (perm & S_IRGRP) ? 'r' : '-';
        permissions[4] = (perm & S_IWGRP) ? 'w' : '-';
        permissions[5] = (perm & S_IXGRP) ? 'x' : '-';
        permissions[6] = (perm & S_IROTH) ? 'r' : '-';
        permissions[7] = (perm & S_IWOTH) ? 'w' : '-';
        permissions[8] = (perm & S_IXOTH) ? 'x' : '-';
        permissions[9] = '\0';
        return 0;
    }
    return 1;
}