#include <stdio.h>
#include <string.h>
#include "client.h"
#include "server.h"

int main(int argc, char *argv[]) {
    int port = 12345; // Port par défaut

    if (argc > 1 && strcmp(argv[1], "server") == 0) {
        startserver(port);

        // Boucle pour traiter les requêtes des clients
        char msg[1024];
        while (getmsg(msg)) {
            printf("Message reçu : %s\n", msg);
        }

        stopserver();
    } else {
        parse_command(argc, argv, port);
    }

    return 0;
}
