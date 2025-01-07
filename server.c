#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "server.h"
#include <dirent.h>
#include "utils.h"

int startserver(int port) {
    printf("Démarrage du serveur sur le port %d\n", port);
    return 0;
}

int stopserver() {
    printf("Arrêt du serveur\n");
    return 0;
}

int getmsg(char msg_read[1024]) {
    char encrypted_msg[1024];
    char decrypted_msg[1024];

    // Simulez la réception d'un message chiffré
    strcpy(encrypted_msg, "Encrypted simulated message");

    // Déchiffrez le message
    decrypt_data(encrypted_msg, strlen(encrypted_msg), decrypted_msg);

    strcpy(msg_read, decrypted_msg);
    return 1;
}

int save_uploaded_file(const char *filename, const char *data) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "uploads/%s", filename);

    FILE *file = fopen(filepath, "wb");
    if (!file) {
        perror("Erreur lors de la création du fichier");
        return -1;
    }

    fwrite(data, 1, strlen(data), file);
    fclose(file);
    printf("Fichier %s sauvegardé avec succès\n", filepath);
    return 0;
}

int list_files(char *response) {
    DIR *d = opendir("uploads/");
    if (!d) {
        perror("Erreur lors de l'ouverture du répertoire uploads/");
        return -1;
    }

    struct dirent *dir;
    strcpy(response, "");
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) { // Fichiers réguliers uniquement
            strcat(response, dir->d_name);
            strcat(response, "\n");
        }
    }
    closedir(d);
    return 0;
}

int send_file_to_client(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier");
        return -1;
    }

    char buffer[1024];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // Envoyer le contenu au client (sndmsg simulé ici)
        printf("Envoi de %lu octets au client\n", bytes_read);
    }

    fclose(file);
    return 0;
}
void handle_client_request(char *msg) {
    if (strncmp(msg, "UPLOAD:", 7) == 0) {
        char filename[256];
        char filedata[768];
        sscanf(msg + 7, "%255[^:]:%767s", filename, filedata);
        save_uploaded_file(filename, filedata);
    } else if (strcmp(msg, "LIST") == 0) {
        char response[1024];
        list_files(response);
        printf("Réponse LIST envoyée au client : %s\n", response);
    } else if (strncmp(msg, "DOWNLOAD:", 9) == 0) {
        char filename[256];
        sscanf(msg + 9, "%255s", filename);
        send_file_to_client(filename);
    } else {
        printf("Commande non reconnue : %s\n", msg);
    }
}
