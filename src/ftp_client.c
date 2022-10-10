#include "ftp_client.h"

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

extern ftp_server_t ftp_server;
void ftp_client_try_run_command_in_worker(ftp_client_t *client, char *command, void(command_function)(ftp_client_t *, char *))
{
    if (client->ssl != NULL)
    {
        puts("WARNING: Running commands in worker are unsupported with tls");
        command_function(client, command);
        return;
    }
    int i;
    for (i = 0; i < WORKER_COUNT; i++)
    {
        if (ftp_server.workers[i].pid == -1)
            break;
    }

    int pid = fork();
    if (pid > 0)
    {
        printf("Worker started %d %d\n", i, pid);
        ftp_server.workers[i].pid = pid;
        ftp_server.workers[i].client = client;
        ftp_server.workers[i].in_progress = 1;
        client->shared_by_processes++;
        return;
    }

    command_function(client, command);
    if (pid == 0)
    {
        ftp_server.workers[i].in_progress = 0;
        exit(0);
    }
}

void ftp_client_setup_tls(ftp_client_t *client)
{
    int flags;
    flags = fcntl(client->socket_fd, F_GETFL, 0);
    fcntl(client->socket_fd, F_SETFL, flags & ~O_NONBLOCK);
    client->ssl = SSL_new(ftp_server.ssl_ctx);
    SSL_set_fd(client->ssl, client->socket_fd);
    if (SSL_accept(client->ssl) <= 0)
    {
        perror("SSL_accept");
        ERR_print_errors_fp(stderr);
    }
    int sock = SSL_get_wfd(client->ssl);
    fcntl(sock, F_SETFL, flags);
}

void ftp_client_set_defaults(ftp_client_t *client, int socket_fd)
{
    memset(client, 0, sizeof(ftp_client_t));
    int flags;
    flags = fcntl(socket_fd, F_GETFL, 0);
    fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);

    client->socket_fd = socket_fd;
    client->welcome_sent = 0;
    client->connected = 1;
    client->shared_by_processes = 0;
    memcpy(client->dir, "/home", sizeof(char[6]));
}

int ftp_client_write_control_message(ftp_client_t *client, const char *buffer, size_t size)
{
    char response[size];
    memcpy(response, buffer, size);
    response[strcspn(response, "\n")] = 0;
    printf("Control response:[%s]\n", response);
    if (client->ssl != NULL)
    {
        return SSL_write(client->ssl, buffer, size);
    }
    return write(client->socket_fd, buffer, size);
}

int ftp_client_write_data_stream(ftp_client_t *client, const char *buffer, size_t size)
{
    int response;
    if (client->connection_mode_data.mode == FTP_NONE_MODE)
    {
        return -1;
    }

    if (client->ssl != NULL)
    {
        response = SSL_write(client->connection_mode_data.ssl, buffer, size);
        if (response < 0)
        {
            ERR_print_errors_fp(stderr);
        }
    }
    else
    {
        response = write(client->connection_mode_data.socket_fd, buffer, size);
    }
    if (response < 0)
    {
        client->connected = 0;
    }
    return response;
}

int _ftp_client_setup_data_transfer_ssl_connection(ftp_client_t *client)
{
    client->connection_mode_data.ssl = SSL_new(ftp_server.ssl_ctx);
    SSL_set_fd(client->connection_mode_data.ssl, client->connection_mode_data.socket_fd);
    if (SSL_accept(client->connection_mode_data.ssl) <= 0)
    {
        puts("Error with SSL_accept");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int _ftp_client_setup_data_transfer_session_passive(ftp_client_t *client)
{
    int addrlen = sizeof(struct sockaddr);
    if ((client->connection_mode_data.socket_fd =
             accept(client->connection_mode_data.server_socket_fd,
                    (struct sockaddr *)&client->connection_mode_data.addr, (socklen_t *)&addrlen)) < 0)
    {
        perror("accept passive");
        return -1;
    }
    return 0;
}

int _ftp_client_setup_data_transfer_session_active(ftp_client_t *client)
{
    if ((client->connection_mode_data.socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    }

    if (connect(client->connection_mode_data.socket_fd,
                (struct sockaddr *)&client->connection_mode_data.addr, sizeof(client->connection_mode_data.addr)) < 0)
    {
        printf("\n Error : Connect Failed \n");
        return 1;
    }

    return 0;
}

int ftp_client_setup_data_transfer_session(ftp_client_t *client)
{
    int status;
    if (client->connection_mode_data.mode == FTP_PASSIVE_MODE)
        status = _ftp_client_setup_data_transfer_session_passive(client);
    else if (client->connection_mode_data.mode == FTP_ACTIVE_MODE)
        status = _ftp_client_setup_data_transfer_session_active(client);

    if (status != 0)
    {
        return status;
    }
    if (client->ssl != NULL)
    {
        return _ftp_client_setup_data_transfer_ssl_connection(client);
    }
    return 1;
}

void ftp_client_setup_active_mode(ftp_client_t *client, char ip[4], int port1, int port2)
{
    memset(&client->connection_mode_data.addr, 0, sizeof(client->connection_mode_data.addr));
    long parsed_ip = 0;
    parsed_ip |= ip[0] << 24;
    parsed_ip |= ip[1] << 16;
    parsed_ip |= ip[2] << 8;
    parsed_ip |= ip[3];
    client->connection_mode_data.addr.sin_family = AF_INET;
    client->connection_mode_data.addr.sin_port = htons((port1 * 256) + port2);
    client->connection_mode_data.addr.sin_addr.s_addr = htonl(parsed_ip);
    client->connection_mode_data.port1 = port1;
    client->connection_mode_data.port2 = port2;
    client->connection_mode_data.mode = FTP_ACTIVE_MODE;
}

void ftp_client_setup_passive_mode(ftp_client_t *client)
{
    srand(time(NULL));
    client->connection_mode_data.port1 = 128 + (rand() % 64);
    client->connection_mode_data.port2 = rand() % 0xff;
    int opt = 1;
    int port = (client->connection_mode_data.port1 * 256) + client->connection_mode_data.port2;
    // Creating socket file descriptor
    if ((client->connection_mode_data.server_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(client->connection_mode_data.server_socket_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    client->connection_mode_data.addr.sin_family = AF_INET;
    client->connection_mode_data.addr.sin_addr.s_addr = INADDR_ANY;
    client->connection_mode_data.addr.sin_port = htons(port);
    // Forcefully attaching socket to the port 8080
    if (bind(client->connection_mode_data.server_socket_fd, (struct sockaddr *)&client->connection_mode_data.addr,
             sizeof(client->connection_mode_data.addr)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(client->connection_mode_data.server_socket_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    client->connection_mode_data.mode = FTP_PASSIVE_MODE;
}

void _ftp_client_clean_up_active_mode(ftp_client_t *client)
{

    close(client->connection_mode_data.socket_fd);
}

void _ftp_client_clean_up_passive_mode(ftp_client_t *client)
{
    close(client->connection_mode_data.socket_fd);
    shutdown(client->connection_mode_data.server_socket_fd, SHUT_RDWR);
}

void ftp_client_clean_up_data_transfer_modes(ftp_client_t *client)
{
    if (client->connection_mode_data.mode == FTP_NONE_MODE)
        return;

    if (client->connection_mode_data.ssl)
    {
        SSL_shutdown(client->connection_mode_data.ssl);
        SSL_free(client->connection_mode_data.ssl);
    }

    if (client->connection_mode_data.mode == FTP_PASSIVE_MODE)
        _ftp_client_clean_up_passive_mode(client);
    else if (client->connection_mode_data.mode == FTP_ACTIVE_MODE)
        _ftp_client_clean_up_active_mode(client);

    client->connection_mode_data.mode = FTP_NONE_MODE;
}

void ftp_client_handle(ftp_client_t *client)
{
    if (!client->welcome_sent)
    {
        char welcome[BUFFER_SIZE] = "220 Welcome \n";
        ftp_client_write_control_message(client, welcome, sizeof(welcome));
        client->welcome_sent = 1;
    }

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    size_t size;
    if (client->ssl != NULL)
    {
        size = SSL_read(client->ssl, buffer, BUFFER_SIZE);
    }
    else
    {
        size = read(client->socket_fd, buffer, BUFFER_SIZE);
    }
    if (size == -1)
    {
        if (errno == EWOULDBLOCK)
        {
            return;
        }
        client->connected = 0;
    }
    else if (size == 0)
    {
        client->connected = 0;
    }
    else if (size > 0)
    {
        handle_command(client, buffer, size);
    }
}

void ftp_client_disconnect(ftp_client_t *client)
{
    ftp_client_clean_up_data_transfer_modes(client);
    close(client->socket_fd);
    if (client->ssl != NULL)
    {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
}