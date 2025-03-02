#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>

char *get_banner()
{
    char *title = "Benvenuto, inserisci le credenziali per accedere al sistema:\n";
    return title;
}

char *get_result()
{
    return "Ciao, benvenuto nel sistema! \n \x20\x20\x20\x20\x20\x20\x7c\x5c\x20\x20\x20\x20\x20\x20\x5f\x2c\x2c\x2c\x2d\x2d\x2d\x2c\x2c\x5f\xa\x5a\x5a\x5a\x7a\x7a\x20\x2f\x2c\x60\x2e\x2d\x27\x60\x27\x20\x20\x20\x20\x2d\x2e\x20\x20\x3b\x2d\x3b\x3b\x2c\x5f\xa\x20\x20\x20\x20\x20\x7c\x2c\x34\x2d\x20\x20\x29\x20\x29\x2d\x2c\x5f\x2e\x20\x2c\x5c\x20\x28\x20\x20\x60\x27\x2d\x27\xa\x20\x20\x20\x20\x27\x2d\x2d\x2d\x27\x27\x28\x5f\x2f\x2d\x2d\x27\x20\x20\x60\x2d\x27\x5c\x5f\x29\x20\x20";
}

// implementing server vulnerable to buffer overflow attacks
int vulnerable_auth_function(char *input)
{
    char buffer[42];
    int result = 0;

    // strcpy is vulnerable to buffer overflow attacks
    // beacuse it does not check the size of the input
    // and an attacker can write more data than the buffer can hold
    // overwriting the cells of the stack memory
    strcpy(buffer, input);

    const char *PASSWORD = "password123";

    if (strcmp(buffer, PASSWORD) == 0)
    {
        printf("Accesso consentito\n");
        result = 1;
    }
    return result;
}

void handle_client(int client_sock)
{
    char *welcome = get_banner();
    send(client_sock, welcome, strlen(welcome), 0);
    char input[1024];
    int input_size;
    sleep(5);
    char *result = get_result();
    input_size = recv(client_sock, input, 1024, 0);

    input[input_size - 1] = '\0';
    if (vulnerable_auth_function(input))
    {
        send(client_sock, result, strlen(result), 0);
    }
    else
    {
        send(client_sock, "Credenziali errate, accesso negato\n", 36, 0);
        close(client_sock);
        return;
    }
    close(client_sock);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Utilizzo corretto: %s <porta>\n", argv[0]);
        return 1;
    }
    int server_sock, client_sock;
    struct sockaddr_in server, client;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (server_sock < 0)
    {
        perror("Errore nella creazione del socket");
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(argv[1]));
    server.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr *)&server, sizeof(server));
    listen(server_sock, 1);

    printf("Server vulnerabile in ascolto sulla porta %s ...\n", argv[1]);

    while (1)
    {
        socklen_t client_len = sizeof(client);
        client_sock = accept(server_sock, (struct sockaddr *)&client, &client_len);
        handle_client(client_sock);
    }

    close(server_sock);
    return 0;
}
