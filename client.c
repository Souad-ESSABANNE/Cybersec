#include <stdio.h>
#include <string.h>
#include "client.h"
#include <openssl/sha.h>
int sndmsg(char msg[1024], int port) {
    
    printf("Envoi du message au port %d : %s\n", port, msg);
    return 0;
}



int upload_file(const char *filename, int port) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier");
        return -1;
    }

    char buffer[1024];
    size_t bytes_read;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    SHA256_Init(&sha256);

    // Lire le fichier par blocs et calculer le hachage
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);

        // Envoyer chaque bloc au serveur
        char msg[1024];
        snprintf(msg, sizeof(msg), "UPLOAD:%s:%s", filename, buffer);
        sndmsg(msg, port);
    }

    SHA256_Final(hash, &sha256);
    fclose(file);

    // Convertir le hachage en chaîne hexadécimale
    char hash_string[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hash_string + (i * 2), 3, "%02x", hash[i]);
    }

    // Envoyer le hachage pour vérification
    char hash_msg[1024];
    snprintf(hash_msg, sizeof(hash_msg), "HASH:%s:%s", filename, hash_string);
    sndmsg(hash_msg, port);

    printf("Fichier téléversé avec succès\n");
    return 0;
}

int download_file(const char *filename, int port) {
    char request[1024];
    snprintf(request, sizeof(request), "DOWNLOAD:%s", filename);
    sndmsg(request, port);

    // Simulation : Recevez le fichier par blocs
    char buffer[1024];
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Erreur lors de la création du fichier");
        return -1;
    }

    // Simulation d'un téléchargement (remplacez par la lecture réelle)
    while (1) {
        // Lire les données (simulation ici)
        strcpy(buffer, "Contenu du fichier...\n");

        if (strlen(buffer) == 0) break;

        fwrite(buffer, 1, strlen(buffer), file);
    }

    fclose(file);
    printf("Fichier %s téléchargé avec succès\n", filename);
    return 0;
}

int request_file_list(int port) {
    char request[1024] = "LIST";
    sndmsg(request, port);
// Simulation : Recevez et affichez la réponse du serveur
    char response[1024];
    strcpy(response, "file1.txt,file2.txt,file3.txt");

    printf("Fichiers disponibles sur le serveur :\n%s\n", response);
    return 0;
}

int parse_command(int argc, char *argv[], int port) {
    if (argc < 2) {
        printf("Usage : sectrans <commande> [arguments]\n");
        printf("Commandes disponibles :\n");
        printf("  -up <file>    : Téléverse un fichier au serveur\n");
        printf("  -list         : Liste les fichiers sur le serveur\n");
        printf("  -down <file>  : Télécharge un fichier depuis le serveur\n");
        return -1;
    }

    if (strcmp(argv[1], "-up") == 0) {
        if (argc < 3) {
            printf("Usage : sectrans -up <file>\n");
            return -1;
        }
        return upload_file(argv[2], port);
    } else if (strcmp(argv[1], "-list") == 0) {
        return request_file_list(port);
    } else if (strcmp(argv[1], "-down") == 0) {
        if (argc < 3) {
            printf("Usage : sectrans -down <file>\n");
            return -1;
        }
        return download_file(argv[2], port);
    } else {
        printf("Commande inconnue : %s\n", argv[1]);
        return -1;
    }
}
#include <openssl/evp.h>

void calculate_sha256(const unsigned char *data, size_t data_len, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();  // Créer un contexte EVP pour le hachage
    if (!ctx) {
        perror("Erreur de création du contexte SHA-256");
        return;
    }

    // Initialiser le contexte pour SHA-256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        perror("Erreur lors de l'initialisation SHA-256");
        EVP_MD_CTX_free(ctx);
        return;
    }

    // Ajouter les données au hachage
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        perror("Erreur lors de la mise à jour SHA-256");
        EVP_MD_CTX_free(ctx);
        return;
    }

    // Finaliser le calcul du hachage
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        perror("Erreur lors de la finalisation SHA-256");
        EVP_MD_CTX_free(ctx);
        return;
    }

    EVP_MD_CTX_free(ctx);  // Libérer le contexte
}
