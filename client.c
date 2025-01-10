#include <stdio.h>
#include <string.h>
#include "client.h"
#include "utils.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/socket.h>   // Pour les sockets
#include <netinet/in.h>   // Pour struct sockaddr_in et INADDR_ANY
#include <arpa/inet.h>    // Pour inet_addr
#include <unistd.h>       // Pour close()
#include <stdbool.h>      // Pour bool, true, false

int sndmsg(char msg[1024], int port) {
    int sock;
    struct sockaddr_in server_addr;

    // Créer le socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[ERREUR] Erreur lors de la création du socket");
        return -1;
    }

    // Configurer l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Se connecter au serveur
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERREUR] Erreur lors de la connexion au serveur");
        close(sock);
        return -1;
    }

    printf("[INFO] Connexion au serveur réussie. Message en cours d'envoi : '%s'\n", msg);

    // Envoyer le message
    if (send(sock, msg, strlen(msg), 0) < 0) {
        perror("[ERREUR] Erreur lors de l'envoi du message");
        close(sock);
        return -1;
    }

    printf("[DEBUG] Message envoyé avec succès.\n");

    // Recevoir une confirmation simple (test)
    char response[1024];
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0) {
    	 printf("[INFO] Réponse reçue du serveur (%d octets) : %s\n", bytes_received, response);
    } else {
	 fprintf(stderr, "[ERREUR] Pas de réponse ou réponse invalide du serveur.\n");
    }

    // Fermer le socket
    close(sock);
    return 0;
}
int download_file(const char *filename, int port) {
    if (!validate_filename(filename)) {
        fprintf(stderr, "[ERREUR] Nom de fichier invalide : %s\n", filename);
        return -1;
    }

    int sock;
    struct sockaddr_in server_addr;
    char request[1024];
    char buffer[1024];
    int bytes_received;

    // Créer le socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[ERREUR] Erreur lors de la création du socket");
        return -1;
    }
    printf("[DEBUG] Socket client créé avec succès : %d\n", sock);

    // Configurer l'adresse du serveur
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Se connecter au serveur
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERREUR] Erreur lors de la connexion au serveur");
        close(sock);
        return -1;
    }
    printf("[DEBUG] Connecté au serveur sur le port %d\n", port);

    // Préparer la requête DOWNLOAD
    snprintf(request, sizeof(request), "DOWNLOAD:%s", filename);

    // Envoyer la requête au serveur
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("[ERREUR] Erreur lors de l'envoi de la commande DOWNLOAD");
        close(sock);
        return -1;
    }
    printf("[INFO] Commande DOWNLOAD envoyée pour le fichier : %s\n", filename);

    // Ouvrir le fichier local pour écrire les données reçues
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("[ERREUR] Erreur lors de la création du fichier local");
        close(sock);
        return -1;
    }
    printf("[DEBUG] Fichier local ouvert pour écriture : %s\n", filename);

    // Recevoir les données
    printf("[DEBUG] Attente de données...\n");
    while (1) {
        // Recevoir la taille des données
        uint32_t size_received;
        bytes_received = recv(sock, &size_received, sizeof(size_received), 0);
        if (bytes_received <= 0) {
            perror("[ERREUR] Erreur lors de la réception de la taille des données");
            fclose(file);
            close(sock);
            return -1;
        }
        size_received = ntohl(size_received); // Convertir en ordre hôte

        // Vérifier si c'est la fin du fichier
        if (size_received == 0) {
            printf("[INFO] Signal de fin de fichier reçu.\n");
            break;
        }

        // Recevoir les données
        bytes_received = recv(sock, buffer, size_received, 0);
        if (bytes_received <= 0) {
            perror("[ERREUR] Erreur lors de la réception des données");
            fclose(file);
            close(sock);
            return -1;
        }
        printf("[INFO] Segment de données reçu (%d octets).\n", bytes_received);

        // Écrire les données reçues dans le fichier
        fwrite(buffer, 1, bytes_received, file);
    }

    fclose(file);
    close(sock);

    printf("[INFO] Fichier %s téléchargé avec succès.\n", filename);
    return 0;
}
int request_file_list(int port) {
    int sock;
    struct sockaddr_in server_addr;

    // Créer le socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[ERREUR] Erreur lors de la création du socket client");
        return -1;
    }

    // Configurer l'adresse du serveur
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Se connecter au serveur
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERREUR] Connexion au serveur échouée");
        close(sock);
        return -1;
    }

    // Envoyer la commande LIST
    char request[1024] = "LIST";
    printf("[DEBUG] Envoi de la commande : '%s'\n", request);
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("[ERREUR] Erreur lors de l'envoi de la commande LIST");
        close(sock);
        return -1;
    }

    // Recevoir la réponse du serveur
    char response[1024];
    char full_response[4096] = ""; // Tampon pour concaténer tous les morceaux
    int bytes_received;

    printf("En attente des données depuis le serveur...\n");
    while ((bytes_received = recv(sock, response, sizeof(response) - 1, 0)) > 0) {
        response[bytes_received] = '\0'; // Terminer la chaîne reçue
 	if (strstr(response, "END_OF_LIST") != NULL) {
            // Retirer le signal "END_OF_LIST" avant d'afficher
            char *end_signal_position = strstr(response, "END_OF_LIST");
            if (end_signal_position) {
                *end_signal_position = '\0'; // Terminer la chaîne avant le signal
            }
            strcat(full_response, response); // Ajouter la partie avant le signal
            printf("[INFO] Signal de fin reçu. Arrêt de la réception.\n");
            break; // Quitter la boucle
        }
        // Concaténer les morceaux dans `full_response`
        strcat(full_response, response);

        // Log des données reçues
        printf(" Données reçues (%d octets) : %s\n", bytes_received, response);
    }

    if (bytes_received < 0) {
        perror("[ERREUR] Erreur lors de la réception de la réponse");
    } else if (bytes_received == 0) {
        printf("[INFO] La connexion avec le serveur a été fermée.\n");
    }

    // Afficher la réponse complète
    printf("[INFO] Liste des fichiers :\n%s\n", full_response);

    close(sock);
    return 0;
}
int upload_file(const char *filename, int port) {
    if (!validate_filename(filename)) {
        fprintf(stderr, "[ERREUR] Nom de fichier invalide : %s\n", filename);
        return -1;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("[ERREUR] Erreur lors de l'ouverture du fichier");
        return -1;
    }

    // Vérifier si le fichier est vide
    fseek(file, 0, SEEK_END); // Se positionner à la fin du fichier
    long file_size = ftell(file); // Obtenir la position actuelle (taille du fichier)
    fseek(file, 0, SEEK_SET); // Revenir au début du fichier

    if (file_size == 0) {
        printf("[INFO] Le fichier %s est vide. Envoi d'un message spécial au serveur.\n", filename);
        char msg[2048];
        snprintf(msg, sizeof(msg), "UPLOAD:%s:EMPTY_FILE", filename);

        if (sndmsg(msg, port) < 0) {
            fclose(file);
            return -1;
        }
        fclose(file);
        return 0; // Succès, mais fichier vide
    }

    char buffer[768];
    size_t bytes_read;
    char encrypted_buffer[1024]; // Tampon pour les données chiffrées
    int encrypted_len;           // Longueur des données chiffrées

    // Lire et envoyer les données par morceaux
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        encrypt_data(buffer, encrypted_buffer, &encrypted_len);

        char msg[2048];
        snprintf(msg, sizeof(msg), "UPLOAD:%s:%.*s", filename, encrypted_len, encrypted_buffer);

        if (sndmsg(msg, port) < 0) {
            fclose(file);
            return -1;
        }
    }

    fclose(file);
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
    }
    else if (strcmp(argv[1], "-login") == 0) {
	    if (argc < 4) {
		printf("Usage : sectrans -login <username> <password>\n");
		return -1;
	    }
	 return authenticate(argv[2], argv[3], port);
    }else if(strcmp(argv[1], "-login") == 0) {
	    if (argc < 4) {
		printf("Usage : sectrans -login <username> <password>\n");
		return -1;
	    }
	    return authenticate(argv[2], argv[3], port);
	}
	    
     else {
        printf("Commande inconnue : %s\n", argv[1]);
        return -1;
    }
}




int authenticate(const char *username, const char *password, int port) {
    int sock;
    struct sockaddr_in server_addr;
    char request[1024], response[1024];

    // Créer le socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[ERREUR] Erreur lors de la création du socket");
        return -1;
    }

    // Configurer l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Se connecter au serveur
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERREUR] Erreur lors de la connexion au serveur");
        close(sock);
        return -1;
    }

    // Envoyer les informations d'authentification
    snprintf(request, sizeof(request), "LOGIN:%s:%s", username, password);
    printf("[DEBUG] Envoi de la commande : %s\n", request);
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("[ERREUR] Erreur lors de l'envoi de la commande LOGIN");
        close(sock);
        return -1;
    }

    // Recevoir la réponse du serveur
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received <= 0) {
        perror("[ERREUR] Erreur lors de la réception de la réponse");
        close(sock);
        return -1;
    }
    response[bytes_received] = '\0';
    printf("[DEBUG] Réponse reçue du serveur : %s\n", response);

    // Vérifier la réponse
    if (strcmp(response, "AUTH_SUCCESS\n") == 0) {
        printf("[INFO] Authentification réussie.\n");
        close(sock);
        return 0;
    } else {
        printf("[INFO] Échec de l'authentification : %s\n", response);
        close(sock);
        return -1;
    }
}

