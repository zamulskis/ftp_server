#ifndef FTP_CLIENT_H
#define FTP_CLIENT_H

#include <netinet/in.h>
#include <stdatomic.h>
#include <openssl/ssl.h>
#define MAX_CREDENTIALS_LENGTH 64

typedef struct connection_mode_data_t
{
    int port1;
    int port2;
    struct sockaddr_in addr;
    int server_socket_fd;
    int socket_fd;
    SSL *ssl;
    SSL_CTX *ssl_ctx;

    enum E_MODE
    {
        FTP_NONE_MODE = 0,
        FTP_PASSIVE_MODE = 1,
        FTP_ACTIVE_MODE = 2,
    } mode;
} connection_mode_data_t;

typedef struct ftp_client_t
{
    int connected;
    int welcome_sent;
    int socket_fd;
    char dir[512];
    char username[MAX_CREDENTIALS_LENGTH];
    char password[MAX_CREDENTIALS_LENGTH];
    atomic_int shared_by_processes;
    connection_mode_data_t connection_mode_data;
    SSL *ssl;
} ftp_client_t;

void ftp_client_set_defaults(ftp_client_t *client, int socket_fd);
void ftp_client_handle(ftp_client_t *client);
int ftp_client_write_data_stream(ftp_client_t *client, const char *buffer, size_t size);
int ftp_client_write_control_message(ftp_client_t *client, const char *buffer, size_t size);
void ftp_client_setup_passive_mode(ftp_client_t *client);
void ftp_client_setup_active_mode(ftp_client_t *client, char ip[4], int port1, int port2);
int ftp_client_setup_data_transfer_session(ftp_client_t *client);
void ftp_client_clean_up_data_transfer_session(ftp_client_t *client);
void ftp_client_clean_up_data_transfer_modes(ftp_client_t *client);
void ftp_client_disconnect(ftp_client_t *client);
void ftp_client_try_run_command_in_worker(ftp_client_t *client, char *command, void(command_function)(ftp_client_t *, char *));
void ftp_client_setup_tls(ftp_client_t *client);
#endif // FTP_CLIENT_H