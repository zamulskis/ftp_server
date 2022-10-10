
#include "ftp_server.h"

#include "ftp_cmd.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/err.h>

#define WORKER_TIMEOUT 5
int SERVER_RUN = 1;

ftp_server_t ftp_server;

int _ftp_server_find_empty_client()
{
    for (int i = 0; i < MAX_CLIENT_COUNT; i++)
    {
        if (ftp_server.client_array[i].value_set == 0)
            return i;
    }
    return -1;
}

void _ftp_server_main_loop()
{
    // int i = 0;
    while (SERVER_RUN)
    {
        int socket_fd;
        int addrlen = sizeof(struct sockaddr);
        socket_fd = accept(ftp_server.socket_fd, (struct sockaddr *)&ftp_server.address,
                           (socklen_t *)&addrlen);
        if (socket_fd == -1)
        {
            if (errno != EWOULDBLOCK)
            {
                perror("error when accepting connection");
                exit(1);
            }
        }
        else
        {
            int client_index = _ftp_server_find_empty_client();
            ftp_client_set_defaults(&ftp_server.client_array[client_index].client, socket_fd);
            ftp_server.client_array[client_index].value_set = 1;
            printf("Client connected: %d\n", socket_fd);
        }
        int i;
        for (i = 0; i < MAX_CLIENT_COUNT; i++)
        {
            ftp_client_t *client = &ftp_server.client_array[i].client;
            if (ftp_server.client_array[i].value_set == 1)
            {
                ftp_client_handle(client);
                if (client->connected == 0 && client->shared_by_processes == 0)
                {
                    printf("Client disconnected: %d\n", client->socket_fd);
                    ftp_server.client_array[i].value_set = 0;
                    ftp_client_disconnect(client);
                }
            }
        }

        for (i = 0; i < WORKER_COUNT; i++)
        {
            if (ftp_server.workers[i].pid == -1)
            {
                continue;
            }

            if (ftp_server.workers[i].in_progress == 0)
            {
                printf("Worker stopped %d %d\n", i, ftp_server.workers[i].pid);
                waitpid(ftp_server.workers[i].pid, 0, 0);
                ftp_server.workers[i].pid = -1;
                ftp_server.workers[i].client->shared_by_processes--;
            }
        }
        usleep(1000);
    }
}

void _ftp_server_start_socket()
{
    int server_fd;
    struct sockaddr_in address;
    int opt = 1 | SOCK_NONBLOCK;

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    int flags = fcntl(server_fd, F_GETFL);

    fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    ftp_server.socket_fd = server_fd;
    ftp_server.address = address;
}

void _ftp_server_setup_ssl()
{

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    ftp_server.ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ftp_server.ssl_ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ftp_server.ssl_ctx, "certs/cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ftp_server.ssl_ctx, "certs/key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void _ftp_server_setup()
{
    _ftp_server_start_socket();
    _ftp_server_setup_ssl();
    memset(ftp_server.client_array, 0, sizeof(ftp_server.client_array));
    ftp_server.workers = create_shared_memory(sizeof(workers_stats_t) * WORKER_COUNT);
    int i;
    for (i = 0; i < WORKER_COUNT; i++)
    {
        ftp_server.workers[i].pid = -1;
    }
}

void _ftp_server_teardown()
{
    int i;
    for (i = 0; i < MAX_CLIENT_COUNT; i++)
    {
        ftp_client_t *client = &ftp_server.client_array[i].client;
        if (ftp_server.client_array[i].value_set == 1)
        {
            ftp_client_disconnect(client);
        }
    }

    SSL_CTX_free(ftp_server.ssl_ctx);
    shutdown(ftp_server.socket_fd, SHUT_RDWR);
    destroy_shared_memory(ftp_server.workers, sizeof(workers_stats_t) * WORKER_COUNT);
}

void sig_handler(int signum)
{
    SERVER_RUN = 0;
    printf("\nInside handler function\n");
}

void ftp_server_start()
{
    signal(SIGINT, sig_handler);
    _ftp_server_setup();
    _ftp_server_main_loop();
    _ftp_server_teardown();
}
