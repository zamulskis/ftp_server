#ifndef FTP_CMD_H
#define FTP_CMD_H
#include "ftp_client.h"
void handle_command(ftp_client_t *client, char *command, size_t size);

#endif // FTP_CMD_H