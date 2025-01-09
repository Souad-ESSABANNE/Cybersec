#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "server.h"
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include "utils.h"
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>  
#include <netinet/in.h>   
#include <arpa/inet.h>  

FILE *log_file = NULL;           
pthread_t worker_thread;         
int worker_thread_created = 0;
int server_socket = -1;
int client_socket = -1;

int startserver(int port) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char buffer[1024];
    bool authenticated = false;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("[ERREUR] Erreur lors de la création du socket serveur");
        return -1;
    }
    printf("[DEBUG] Socket serveur créé avec succès : %d\n", server_socket);
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[ERREUR] Erreur lors de setsockopt");
        close(server_socket);
        return -1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERREUR] Erreur lors de la liaison du socket");
        close(server_socket);
        return -1;
    }
    printf("[DEBUG] Liaison réussie.\n");

    if (listen(server_socket, 5) < 0) {
        perror("[ERREUR] Erreur lors de l'écoute sur le socket");
        close(server_socket);
        return -1;
    }
    printf("[DEBUG] Serveur en écoute sur le port %d\n", port);

    bool running = true;
    while (running) {
        printf("[INFO] En attente de connexion...\n");
        client_len = sizeof(client_addr);

        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("[ERREUR] Erreur lors de l'acceptation de la connexion");
            continue;
        }
        printf("[DEBUG] Client connecté.\n");

        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                if (bytes_received == 0) {
                    printf("[INFO] Connexion fermée par le client.\n");
                } else {
                    perror("[ERREUR] Erreur lors de la réception.");
                }
                break;
            }
            buffer[bytes_received] = '\0';
            printf("[DEBUG] Message reçu : %s\n", buffer);
	    if (!authenticated) {
		if (strncmp(buffer, "LOGIN:", 6) == 0) {
		    authenticated = handle_authentication(buffer, client_socket);
		    continue; // Passe à la commande suivante après authentification
		} else {
		    const char *error_response = "ERREUR: Non authentifié.\n";
		    send(client_socket, error_response, strlen(error_response), 0);
		    printf("[ERREUR] Commande reçue sans authentification préalable.\n");
		    continue;
		}
	    }
            if (strcmp(buffer, "LIST") == 0) {
	    	char response[1024];
	    	if (list_files(response) == 0) {
		printf("[DEBUG] Taille de la réponse LIST : %lu octets\n",strlen(response)); 
		if (send(client_socket, response, strlen(response), 0) < 0) {
		    perror("[ERREUR] Erreur lors de l'envoi de la réponse LIST");
		} else {
		    printf("[INFO] Réponse LIST envoyée au client.\n");
		}
		usleep(100000);
	    } else {
		const char *error_response = "Erreur lors de l'accès au répertoire uploads/\n";
		send(client_socket, error_response, strlen(error_response), 0);
	    }
	} else if (strncmp(buffer, "UPLOAD:",7) == 0) {
	    printf("[INFO] Commande UPLOAD reçue.\n");

	    // Extraction du nom de fichier et du contenu
	    char filename[256];
	    char filedata[768];
	    sscanf(buffer + 7, "%255[^:]:%767[^\n]", filename, filedata);

	    // Sauvegarde du fichier
	    if (save_uploaded_file(filename, filedata) == 0) {
		const char *success_msg = "Fichier uploadé avec succès.\n";
		send(client_socket, success_msg, strlen(success_msg), 0);
		printf("[INFO] Fichier %s sauvegardé avec succès.\n", filename);
	    } else {
		const char *error_msg = "Erreur lors de l'upload du fichier.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
		printf("[ERREUR] Échec de la sauvegarde du fichier %s.\n", filename);
	    }

	}
	else if (strncmp(buffer, "DOWNLOAD:", 9) == 0) {
	    printf("[DEBUG] Traitement de la commande DOWNLOAD avec buffer : %s\n", buffer);

	    char filename[256];
	    int scan_result = sscanf(buffer + 9, "%255s", filename);
	    if (scan_result != 1) {
		printf("[ERREUR] Échec de l'extraction du nom du fichier depuis buffer.\n");
		const char *error_msg = "Erreur : Commande mal formée.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
		continue;
	    }
	    printf("[INFO] Demande de téléchargement pour le fichier : %s\n", filename);

	    if (send_file_to_client(client_socket, filename) == 0) {
		printf("[INFO] Fichier %s envoyé avec succès.\n", filename);
	    } else {
		const char *error_msg = "Erreur : Impossible de télécharger le fichier demandé.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
	    }
	}
	else {
                const char *error_response = "Commande inconnue wakwak\n";
                send(client_socket, error_response, strlen(error_response), 0);
            }
        }
        usleep(10000);
        close(client_socket);
        client_socket = -1;
    }

    return stopserver();
}

// Fonction stopserver pour arrêter proprement le serveur
int stopserver() {
    printf("Arrêt du serveur\n");
    if (client_socket != -1) {
        close(client_socket);
        printf("[DEBUG] Socket client fermé : %d\n", client_socket);
        client_socket = -1;
    }
    // Fermer le socket serveur, s'il est ouvert
    if (server_socket != -1) {
        close(server_socket);
        printf("[DEBUG] Socket serveur fermé : %d\n", server_socket);
        server_socket = -1;
    }

    // Fermer le socket client, s'il est ouvert
   

    printf("Le serveur a été arrêté proprement\n");
    return 0;
}
int getmsg(char msg_read[1024]) {
    char encrypted_msg[1024];
    char decrypted_msg[1024];

    // Simulez la réception d'un message chiffré
    int bytes_received = recv(client_socket, encrypted_msg, sizeof(encrypted_msg) - 1, 0);
    if (bytes_received <= 0) {
        perror("Erreur lors de la réception du message");
        return -1;
    }

    encrypted_msg[bytes_received] = '\0';
    printf("Message chiffré reçu : %s\n", encrypted_msg);

    // Déchiffrez le message
    decrypt_data(encrypted_msg, bytes_received, decrypted_msg);

    // Vérifier si le déchiffrement a échoué
    if (strlen(decrypted_msg) == 0) {
        fprintf(stderr, "Erreur lors de la finalisation du déchiffrement\n");
        return -1;
    }

    printf("Message déchiffré : %s\n", decrypted_msg);
    strcpy(msg_read, decrypted_msg);
    return 1;
}

int save_uploaded_file(const char *filename, const char *data) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "uploads/%s", filename);

    FILE *file = fopen(filepath, "ab"); // 'ab' pour ajouter si le fichier existe déjà
    if (!file) {
        perror("[ERREUR] Erreur lors de la création/écriture du fichier");
        return -1;
    }

    size_t written = fwrite(data, 1, strlen(data), file);
    if (written < strlen(data)) {
        perror("[ERREUR] Erreur lors de l'écriture des données");
        fclose(file);
        return -1;
    }

    fclose(file);
    printf("[INFO] Fichier %s sauvegardé avec succès\n", filepath);
    return 0;
}

int list_files(char *response) {
    DIR *dir = opendir("uploads/");
    if (!dir) {
        perror("[ERREUR] Impossible d'ouvrir le répertoire uploads/");
        strcpy(response, "Erreur : Impossible d'accéder au répertoire uploads/\n");
        return -1;
    }

    struct dirent *entry;
    strcpy(response, ""); // Initialiser la réponse

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // Fichiers réguliers uniquement
            printf("[DEBUG] Fichier trouvé : %s\n", entry->d_name); // Log du fichier trouvé
            strcat(response, entry->d_name);
            strcat(response, "\n");
        }
    }
    closedir(dir);

    // Si aucun fichier trouvé
    if (strlen(response) == 0) {
        strcpy(response, "Aucun fichier disponible.\n");
    }

    return 0;
}

void handle_client_request(const char *msg) {
    if (strncmp(msg, "UPLOAD:", 7) == 0) {
          char filename[256];
	    char filedata[768];

	    // Extraire le nom du fichier et le contenu du message
	    sscanf(msg + 7, "%255[^:]:%767s", filename, filedata);

	    // Sauvegarder le fichier
	    if (save_uploaded_file(filename, filedata) < 0) {
		const char *error_response = "Erreur lors de la sauvegarde du fichier.\n";
		send(client_socket, error_response, strlen(error_response), 0);
	    } else {
		const char *success_response = "Fichier uploadé avec succès.\n";
		send(client_socket, success_response, strlen(success_response), 0);
	    }
    } else if (strcmp(msg, "LIST") == 0) {
        char response[1024];
	    if (list_files(response) == 0) {
		printf("[DEBUG] Réponse LIST générée :\n%s\n", response); // Log de la réponse
		if (send(client_socket, response, strlen(response), 0) < 0) {
		    perror("[ERREUR] Erreur lors de l'envoi de la réponse LIST");
		} else {
		    printf("[INFO] Réponse LIST envoyée au client.\n");
		}
	    } else {
		const char *error_response = "Erreur lors de l'accès au répertoire uploads/\n";
		send(client_socket, error_response, strlen(error_response), 0);
	    }
    } else if (strncmp(msg, "DOWNLOAD:", 9) == 0) {
	    char filename[256];
	    sscanf(msg + 9, "%255s", filename); // Extraire le nom du fichier
	    printf("[INFO] Demande de téléchargement pour le fichier : %s\n", filename);
	    if (send_file_to_client(client_socket, filename) < 0) {
		const char *error_msg = "Erreur : Impossible de télécharger le fichier demandé.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
	    } else {
		printf("[INFO] Fichier %s envoyé avec succès.\n", filename);
	    }
}  else {
        printf("Commande non reconnue : %s\n", msg);
    }
}

int send_file_to_client(int socket, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("[ERREUR] Erreur lors de l'ouverture du fichier");
        return -1;
    }

    char buffer[1024];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(socket, buffer, bytes_read, 0) < 0) {
            perror("[ERREUR] Erreur lors de l'envoi du fichier au client");
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    printf("[INFO] Fichier %s envoyé complètement.\n", filename);
    return 0;
}



int handle_authentication(const char *msg, int client_socket) {
    char username[50], password[50];
    // Extraire le nom d'utilisateur et le mot de passe du message
    if (sscanf(msg, "LOGIN:%49[^:]:%49s", username, password) != 2) {
        const char *error_response = "AUTH_FAIL: Format incorrect.\n";
        send(client_socket, error_response, strlen(error_response), 0);
        printf("[ERREUR] Format incorrect de la commande LOGIN.\n");
        return 0; // Échec d'authentification
    }

    // Vérification des informations d'identification
    if (strcmp(username, "admin") == 0 && strcmp(password, "password") == 0) {
        const char *success_response = "AUTH_SUCCESS\n";
        send(client_socket, success_response, strlen(success_response), 0);
        printf("[INFO] Authentification réussie pour l'utilisateur : %s\n", username);
        return 1; // Authentification réussie
    } else {
        const char *error_response = "AUTH_FAIL: Nom d'utilisateur ou mot de passe incorrect.\n";
        send(client_socket, error_response, strlen(error_response), 0);
        printf("[ERREUR] Échec de l'authentification pour l'utilisateur : %s\n", username);
        return 0; // Échec d'authentification
    }
}
