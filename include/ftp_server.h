#ifndef FTP_SERVER_H
#define FTP_SERVER_H

#include "ftp_client.h"

#include <openssl/ssl.h>
#define WORKER_COUNT 8
#define PORT 8080
#define MAX_CLIENT_COUNT 128

typedef struct
{
    int pid;
    atomic_char in_progress;
    ftp_client_t *client;
} workers_stats_t;

typedef struct
{
    int shm_size;
    int socket_fd;
    struct sockaddr_in address;
    workers_stats_t *workers;
    SSL_CTX *ssl_ctx;
    struct
    {
        char value_set;
        ftp_client_t client;
    } client_array[MAX_CLIENT_COUNT];
} ftp_server_t;

void ftp_server_start();

#endif // FTP_SERVER_H