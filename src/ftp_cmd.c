#include "ftp_cmd.h"

#include "ftp_server.h"
#include "ftp_client.h"
#include "utils.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>

#define MAX_FILE_PATH 512
extern ftp_server_t ftp_server;
void _ftp_LIST(ftp_client_t *client, char *command)
{
    char *response = "150 File status okay; about to open data connection.\n";
    ftp_client_write_control_message(client, response, strlen(response));
    if (ftp_client_setup_data_transfer_session(client) != 0)
    {
        char *response = "425 Can't open data connection.\n";
        ftp_client_write_control_message(client, response, strlen(response));
        return;
    }

    DIR *d;
    struct dirent *dir;
    d = opendir(client->dir);
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            char d_type = '-';
            if (dir->d_type == DT_DIR)
            {
                d_type = 'd';
            }
            char file[BUFFER_SIZE];
            char path[MAX_FILE_PATH];
            char permissions[10];
            memset(file, 0, BUFFER_SIZE);
            memset(path, 0, MAX_FILE_PATH);
            memset(permissions, '-', sizeof(permissions));
            strcat(path, client->dir);
            strcat(path, dir->d_name);
            get_file_permissions(path, permissions);
            sprintf(file, "%c%s 3 slacker users 104 Jul 27 01:45 %s\n", d_type, permissions, dir->d_name);
            if (ftp_client_write_data_stream(client, file, strlen(file)) < 0)
            {
                char *response = "Connection closed; transfer aborted.\n";
                ftp_client_write_control_message(client, response, strlen(response));
                return;
            }
        }
        closedir(d);
    }
    ftp_client_clean_up_data_transfer_modes(client);

    char *response_completed = "226 Directory send OK.\n";
    ftp_client_write_control_message(client, response_completed, strlen(response_completed));
}

void _ftp_RETR(ftp_client_t *client, char *command)
{
    char *dir = strchr(command, ' ') + 1;
    char *dir_end = strchr(dir, '\r');
    memset(dir_end, 0, 1);
    char file_contents[254];
    char path[BUFFER_SIZE];
    memset(path, 0, BUFFER_SIZE);
    sprintf(path, "%s/%s", client->dir, dir);
    FILE *ptr;
    if ((ptr = fopen(path, "rb")) == NULL)
    {
        perror(path);
        char error[254] = "550 ";
        strcat(error, strerror(errno));
        strcat(error, "\n");
        ftp_client_write_control_message(client, error, strlen(error));
        return;
    }

    char *response = "150 File status okay; about to open data connection.\n";
    ftp_client_write_control_message(client, response, strlen(response));

    if (ftp_client_setup_data_transfer_session(client) != 0)
    {
        ftp_client_clean_up_data_transfer_modes(client);
        char *response = "425 Can't open data connection.\n";
        ftp_client_write_control_message(client, response, strlen(response));
        fclose(ptr);
        return;
    }

    size_t size;
    while ((size = fread(file_contents, sizeof(file_contents), 1, ptr)) > 0)
    {
        if (ftp_client_write_data_stream(client, file_contents, size) < 0)
        {
            char *response = "Connection closed; transfer aborted.\n";
            ftp_client_write_control_message(client, response, strlen(response));
            return;
        }
    }
    fclose(ptr);
    ftp_client_clean_up_data_transfer_modes(client);

    char *response_completed = "226 Directory send OK.\n";
    ftp_client_write_control_message(client, response_completed, strlen(response_completed));
}

void _ftp_PORT(ftp_client_t *client, char *command)
{
    char ip[4];
    int port1, port2;
    char *params = strchr(command, ' ') + 1;
    char *begin = params;
    char *end = strchr(params, ',');
    ip[0] = (int)strtol(begin, &end, 0);
    begin = end + 1;
    end = strchr(params, ',');
    ip[1] = (int)strtol(begin, &end, 0);
    begin = end + 1;
    end = strchr(params, ',');
    ip[2] = (int)strtol(begin, &end, 0);
    begin = end + 1;
    end = strchr(params, ',');
    ip[3] = (int)strtol(begin, &end, 0);
    begin = end + 1;
    end = strchr(params, ',');
    port1 = (int)strtol(begin, &end, 0);
    begin = end + 1;
    end = strchr(params, ',');
    port2 = (int)strtol(begin, &end, 0);
    ftp_client_clean_up_data_transfer_modes(client);
    ftp_client_setup_active_mode(client, ip, port1, port2);
    char response[BUFFER_SIZE] = "331 Enter password \n";
    ftp_client_write_control_message(client, response, strlen(response));
}

void _ftp_AUTH(ftp_client_t *client, char *command)
{
    char response[BUFFER_SIZE] = "234 AUTH ALLOWED \n";
    ftp_client_write_control_message(client, response, strlen(response));
    ftp_client_setup_tls(client);
}
void _ftp_USER(ftp_client_t *client, char *command)
{
    char response[BUFFER_SIZE] = "331 Enter password \n";
    ftp_client_write_control_message(client, response, strlen(response));
}

void _ftp_PASS(ftp_client_t *client, char *command)
{
    char response[BUFFER_SIZE] = "220 Enter password \n";
    ftp_client_write_control_message(client, response, strlen(response));
}

void _ftp_PWD(ftp_client_t *client, char *command)
{
    char response[BUFFER_SIZE];
    sprintf(response, "220 %s \n", client->dir);
    ftp_client_write_control_message(client, response, strlen(response));
}

void _ftp_TYPE(ftp_client_t *client, char *command)
{
    char response[BUFFER_SIZE] = "220 \n";
    ftp_client_write_control_message(client, response, strlen(response));
}

void _ftp_PASV(ftp_client_t *client, char *command)
{
    ftp_client_clean_up_data_transfer_modes(client);
    int ip[4];
    ftp_client_setup_passive_mode(client);
    get_ip(ftp_server.socket_fd, ip);
    char buffer[48];
    sprintf(buffer, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d) \n",
            ip[0], ip[1], ip[2], ip[3], client->connection_mode_data.port1, client->connection_mode_data.port2);
    ftp_client_write_control_message(client, buffer, strlen(buffer));
}

void _ftp_CWD(ftp_client_t *client, char *command)
{
    char *dir = strchr(command, ' ') + 1;
    char *dir_end = strchr(dir, '\r');
    if (strcmp(dir, "..") == 0)
    {
        char *substr = strrchr(client->dir, '/');
        memset(substr, 0, sizeof(client->dir) - (client->dir - substr));
    }
    else if (dir[0] == '/')
    {
        size_t dir_length = dir_end - dir;
        memcpy(client->dir, dir, dir_length);
        memset(client->dir + dir_length, 0, sizeof(client->dir) - (dir_length));
    }
    else
    {
        if (client->dir[strlen(client->dir) - 1] != '/')
            strcat(client->dir, "/");
        strncat(client->dir, dir, dir_end - dir);
    }
    printf("CLIENT DIR:  %s\n", client->dir);
    char response[BUFFER_SIZE] = "250 Directory successfully changed.\n";
    ftp_client_write_control_message(client, response, strlen(response));
}

void _ftp_SYST(ftp_client_t *client, char *command)
{
    char response[BUFFER_SIZE] = "215 UNIX Type: L8.\n";
    ftp_client_write_control_message(client, response, strlen(response));
}

void _ftp_PBSZ(ftp_client_t *client, char *command)
{
    char response[BUFFER_SIZE] = "200 \n";
    ftp_client_write_control_message(client, response, strlen(response));
}

void _ftp_PORT_P(ftp_client_t *client, char *command)
{
    char response[BUFFER_SIZE] = "200 \n";
    ftp_client_write_control_message(client, response, strlen(response));
}

typedef struct
{
    char *command;
    void (*function)(ftp_client_t *, char *);
    char run_in_worker;

} ftp_command_t;

const ftp_command_t commands[] = {
    {.command = "PWD", .function = _ftp_PWD, .run_in_worker = 0},
    {.command = "LIST", .function = _ftp_LIST, .run_in_worker = 1},
    {.command = "RETR", .function = _ftp_RETR, .run_in_worker = 1},
    {.command = "USER", .function = _ftp_USER, .run_in_worker = 0},
    {.command = "PASS", .function = _ftp_PASS, .run_in_worker = 0},
    {.command = "TYPE", .function = _ftp_TYPE, .run_in_worker = 0},
    {.command = "CWD", .function = _ftp_CWD, .run_in_worker = 0},
    {.command = "PORT", .function = _ftp_PORT, .run_in_worker = 0},
    {.command = "PASV", .function = _ftp_PASV, .run_in_worker = 0},
    {.command = "AUTH", .function = _ftp_AUTH, .run_in_worker = 0},
    {.command = "PBSZ", .function = _ftp_PBSZ, .run_in_worker = 0},
    {.command = "SYST", .function = _ftp_SYST, .run_in_worker = 0},
    {.command = "PROT P", .function = _ftp_PORT_P, .run_in_worker = 0},
};

void handle_command(ftp_client_t *client, char *command, size_t size)
{
    char printable_command[BUFFER_SIZE];
    memcpy(printable_command, command, BUFFER_SIZE);
    printable_command[strcspn(printable_command, "\r\n")] = 0;
    printf("Command received:[%s]\n", printable_command);
    int i = 0;
    for (i = 0; i < sizeof(commands) / sizeof(ftp_command_t); i++)
    {
        if (strncmp(command, commands[i].command, strlen(commands[i].command)) == 0)
        {
            if (commands[i].run_in_worker)
            {
                ftp_client_try_run_command_in_worker(client, command, commands[i].function);
                return;
            }
            else
            {
                return commands[i].function(client, command);
            }
        }
    }
    puts("ERROR: Unknown command\n");
    char response[BUFFER_SIZE] = "502 command not implemented \n";
    ftp_client_write_control_message(client, response, strlen(response));
}