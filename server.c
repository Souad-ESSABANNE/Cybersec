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
#include <openssl/rand.h>
#include <openssl/evp.h>

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
        perror("[ERREUR] Erreur lors de la creation du socket serveur");
        return -1;
    }
    printf("[DEBUG] Socket serveur cree avec succès : %d\n", server_socket);
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
    printf("[DEBUG] Liaison reussie.\n");

    if (listen(server_socket, 5) < 0) {
        perror("[ERREUR] Erreur lors de l'ecoute sur le socket");
        close(server_socket);
        return -1;
    }
    printf("[DEBUG] Serveur en ecoute sur le port %d\n", port);

    bool running = true;
    while (running) {
        printf("[INFO] En attente de connexion...\n");
        client_len = sizeof(client_addr);

        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("[ERREUR] Erreur lors de l'acceptation de la connexion");
            continue;
        }
       

        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                if (bytes_received == 0) {
                   printf("[INFO] Connexion terminee par le client (IP : %s).\n", inet_ntoa(client_addr.sin_addr));
                } else {
                    perror("[ERREUR] Erreur lors de la reception.");
                }
                break;
            }
            buffer[bytes_received] = '\0';
            printf("[INFO] Commande reçue : %s\n", buffer);
	    if (!authenticated) {
		if (strncmp(buffer, "LOGIN:", 6) == 0) {
		    authenticated = handle_authentication(buffer, client_socket);
		    continue; // Passe à la commande suivante après authentification
		} else {
		    const char *error_response = "ERREUR: Non authentifie.\n";
		    send(client_socket, error_response, strlen(error_response), 0);
		    printf("[ERREUR] Commande reçue sans authentification prealable.\n");
		    continue;
		}
	    }
            if (strcmp(buffer, "LIST") == 0) {
	    	char response[1024];
	    	if (list_files(response) == 0) {
		printf("[DEBUG] Taille de la reponse LIST : %lu octets\n",strlen(response)); 
		if (send(client_socket, response, strlen(response), 0) < 0) {
		    perror("[ERREUR] Erreur lors de l'envoi de la reponse LIST");
		} else {
		    printf("[INFO] Reponse LIST envoyee au client.\n");
		}
		usleep(100000);
	    } else {
		const char *error_response = "Erreur lors de l'accès au repertoire uploads/\n";
		send(client_socket, error_response, strlen(error_response), 0);
	    }
	} else if (strncmp(buffer, "UPLOAD:",7) == 0) {
	    // Extraction du nom de fichier et du contenu
	    char filename[256];
	    char filedata[768];
	    sscanf(buffer + 7, "%255[^:]:%767[^\n]", filename, filedata);
            printf("[INFO] Commande UPLOAD reçue pour le fichier : %s\n", filename);

	    // Sauvegarde du fichier
	    if (save_uploaded_file(filename, filedata) == 0) {
		const char *success_msg = "Fichier uploade avec succès.\n";
		send(client_socket, success_msg, strlen(success_msg), 0);
		printf("[INFO] Fichier %s sauvegarde avec succès.\n", filename);
	    } else {
		const char *error_msg = "Erreur lors de l'upload du fichier.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
		printf("[ERREUR] Echec de la sauvegarde du fichier %s.\n", filename);
	    }

	}
	else if (strncmp(buffer, "DOWNLOAD:", 9) == 0) {
	    printf("[DEBUG] Traitement de la commande DOWNLOAD avec buffer : %s\n", buffer);

	    char filename[256];
	    int scan_result = sscanf(buffer + 9, "%255s", filename);
	    if (scan_result != 1) {
		printf("[ERREUR] echec de l'extraction du nom du fichier depuis buffer.\n");
		const char *error_msg = "Erreur : Commande mal formee.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
		continue;
	    }
	    printf("[INFO] Demande de telechargement pour le fichier : %s\n", filename);

	    if (send_file_to_client(client_socket, filename) == 0) {
		printf("[INFO] Fichier %s envoye avec succès.\n", filename);
	    } else {
		const char *error_msg = "Erreur : Impossible de telecharger le fichier demande.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
	    }
	}
	else {
                const char *error_response = "Commande inconnue \n";
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
        printf("[DEBUG] Socket client ferme : %d\n", client_socket);
        client_socket = -1;
    }
    // Fermer le socket serveur, s'il est ouvert
    if (server_socket != -1) {
        close(server_socket);
        printf("[DEBUG] Socket serveur ferme: %d\n", server_socket);
        server_socket = -1;
    }

    // Fermer le socket client, s'il est ouvert
   

    printf("Le serveur a ete arrête proprement\n");
    return 0;
}
int getmsg(char msg_read[1024]) {
    char encrypted_msg[1024];
    char decrypted_msg[1024];

    // Simulez la réception d'un message chiffré
    int bytes_received = recv(client_socket, encrypted_msg, sizeof(encrypted_msg) - 1, 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "[ERREUR] Echec de reception ");
        return -1;
    }

    encrypted_msg[bytes_received] = '\0';
    printf("Message chiffre reçu : %s\n", encrypted_msg);

    // Déchiffrez le message
    decrypt_data(encrypted_msg, bytes_received, decrypted_msg);

    // Vérifier si le déchiffrement a échoué
    if (strlen(decrypted_msg) == 0) {
        fprintf(stderr, "Erreur lors de la finalisation du dechiffrement\n");
        return -1;
    }

    printf("Message dechiffre : %s\n", decrypted_msg);
    strcpy(msg_read, decrypted_msg);
    return 1;
}

int save_uploaded_file(const char *filename, const char *data) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "uploads/%s", filename);

    FILE *file = fopen(filepath, "ab"); // 'ab' pour ajouter si le fichier existe déjà
    if (!file) {
        perror("[ERREUR] Erreur lors de la creation/ecriture du fichier");
        return -1;
    }

    size_t written = fwrite(data, 1, strlen(data), file);
    if (written < strlen(data)) {
        perror("[ERREUR] Erreur lors de l'ecriture des donnees");
        fclose(file);
        return -1;
    }

    fclose(file);
    printf("[INFO] Fichier %s sauvegarde avec succès\n", filepath);
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
            // Ajouter le nom du fichier et une nouvelle ligne
            strcat(response, entry->d_name);
            strcat(response, "\n");
        }
    }
    closedir(dir);

    // Si aucun fichier trouvé
    if (strlen(response) == 0) {
        strcpy(response, "Aucun fichier disponible.\n");
    } else {
        // Ajouter le signal de fin
        strcat(response, "END_OF_LIST\n");
    }

    return 0; // Succès
}

void handle_client_request(const char *msg) {
    if (strncmp(msg, "UPLOAD:", 7) == 0) {
          char filename[256];
	  char filedata[768];
          char encrypted_data[1024];
          char decrypted_data[1024];
         int decrypted_len;
	    // Extraire le nom du fichier et le contenu du message
	    sscanf(msg + 7, "%255[^:]:%767s", filename, filedata);
	    decrypt_data(encrypted_data, strlen(encrypted_data), decrypted_data);
	    // Sauvegarder le fichier
	    if (save_uploaded_file(filename, decrypted_data) < 0) {
		 const char *success_msg = "Fichier uploade et dechiffre avec succès.\n";
		send(client_socket, success_msg, strlen(success_msg), 0);
		printf("[INFO] Fichier %s dechiffre et sauvegarde avec succès.\n", filename);
	    } else {
		const char *error_msg = "Erreur lors de la sauvegarde du fichier dechiffre.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
		printf("[ERREUR] Echec de la sauvegarde du fichier dechiffre %s.\n", filename);
	    }
    } else if (strcmp(msg, "LIST") == 0) {
        char response[1024];
	    if (list_files(response) == 0) {
		printf("[DEBUG] Reponse LIST generee :\n%s\n", response); // Log de la réponse
		if (send(client_socket, response, strlen(response), 0) < 0) {
		    perror("[ERREUR] Erreur lors de l'envoi de la reponse LIST");
		} else {
		    printf("[INFO] Reponse LIST envoyee au client.\n");
		}
	    } else {
		const char *error_response = "Erreur lors de l'accès au repertoire uploads/\n";
		send(client_socket, error_response, strlen(error_response), 0);
	    }
    } else if (strncmp(msg, "DOWNLOAD:", 9) == 0) {
	    char filename[256];
	    sscanf(msg + 9, "%255s", filename); // Extraire le nom du fichier
	    printf("[INFO] Demande de telechargement pour le fichier : %s\n", filename);
	    if (access(filename, F_OK) != 0) {
		perror("[ERREUR] Fichier non trouve");
		const char *error_msg = "Erreur : Fichier non trouve.\n";
		send(client_socket, error_msg, strlen(error_msg), 0);
		return;
	    }
	    if (send_file_to_client(client_socket, filename) < 0) {
	        printf("[INFO] Fichier %s envoye avec succès.\n", filename);
	    } else {
		 const char *error_msg = "Erreur : Impossible d'envoyer le fichier.\n";
       		 send(client_socket, error_msg, strlen(error_msg), 0);
	    }
}  else if (strncmp(msg, "LOGIN:", 6) == 0) {
	    char username[50], password[50];
            sscanf(msg + 6, "%49[^:]:%49s", username, password);
		// Simulation d'authentification
	       if (strcmp(username, "admin") == 0 && strcmp(password, "password") == 0) {
	           printf("[INFO] Authentification reussie pour l'utilisateur : %s\n", username);
	    const char *success_response = "AUTH_SUCCESS\n";
	    int sent_bytes = send(client_socket, success_response, strlen(success_response), 0);
	    if (sent_bytes < 0) {
		perror("[ERREUR] Erreur lors de l'envoi de AUTH_SUCCESS");
	    } else {
		printf("[DEBUG] AUTH_SUCCESS envoye : %d octets\n", sent_bytes);
	    }
	} else {
	    printf("[INFO] Echec de l'authentification pour l'utilisateur : %s\n", username);
	    const char *fail_response = "AUTH_FAIL\n";
	    int sent_bytes = send(client_socket, fail_response, strlen(fail_response), 0);
	    if (sent_bytes < 0) {
		perror("[ERREUR] Erreur lors de l'envoi de AUTH_FAIL");
	    } else {
		printf("[DEBUG] AUTH_FAIL envoye : %d octets\n", sent_bytes);
	    }
	}
        usleep(100000); // 100 ms
	}
else {
        printf("Commande non reconnue : %s\n", msg);
    }
}

int send_file_to_client(int socket, const char *filename) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "uploads/%s", filename);
    printf("[DEBUG] Chemin du fichier : %s\n", filepath);

    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("[ERREUR] Erreur lors de l'ouverture du fichier");
        return -1;
    }

    char buffer[1024];                 // Tampon pour les données brutes
    unsigned char encrypted_buffer[1024]; // Tampon pour les données chiffrées
    size_t bytes_read;
    int encrypted_len;

    // Générer un IV
    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) {
        perror("[ERREUR] Impossible de générer l'IV");
        fclose(file);
        return -1;
    }

    // Envoyer l'IV au client
    if (send(socket, iv, sizeof(iv), 0) < 0) {
        perror("[ERREUR] Erreur lors de l'envoi de l'IV");
        fclose(file);
        return -1;
    }
    printf("[INFO] IV envoyé au client.\n");

    // Préparer le contexte de chiffrement
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("[ERREUR] Impossible de créer le contexte de chiffrement");
        fclose(file);
        return -1;
    }

    const unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        perror("[ERREUR] Erreur lors de l'initialisation du chiffrement");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return -1;
    }
    printf("[INFO] Envoi du fichier : %s\n", filename);

    // Lire et chiffrer les données
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_EncryptUpdate(ctx, encrypted_buffer, &encrypted_len, (unsigned char *)buffer, bytes_read) != 1) {
            perror("[ERREUR] Erreur lors du chiffrement des données");
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return -1;
        }

        // Envoyer la taille des données chiffrées
        uint32_t size_to_send = htonl(encrypted_len);
        if (send(socket, &size_to_send, sizeof(size_to_send), 0) < 0) {
            perror("[ERREUR] Erreur lors de l'envoi de la taille des données chiffrées");
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return -1;
        }

        // Envoyer les données chiffrées
        if (send(socket, encrypted_buffer, encrypted_len, 0) < 0) {
            perror("[ERREUR] Erreur lors de l'envoi des données chiffrées");
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return -1;
        }
        printf("[DEBUG] Données chiffrées envoyées (hex) : ");
        for (int i = 0; i < encrypted_len; i++) {
            printf("%02x", encrypted_buffer[i]);
        }
        printf("\n");
    }

    // Finaliser le chiffrement
    if (EVP_EncryptFinal_ex(ctx, encrypted_buffer, &encrypted_len) != 1) {
        perror("[ERREUR] Erreur lors de la finalisation du chiffrement");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    // Envoyer la taille des données finales
    uint32_t final_size_to_send = htonl(encrypted_len);
    if (send(socket, &final_size_to_send, sizeof(final_size_to_send), 0) < 0) {
        perror("[ERREUR] Erreur lors de l'envoi de la taille des données finales");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    // Envoyer les données finales chiffrées
    if (send(socket, encrypted_buffer, encrypted_len, 0) < 0) {
        perror("[ERREUR] Erreur lors de l'envoi des données finales chiffrées");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    // Envoyer un signal de fin
    uint32_t end_signal = htonl(0);
    if (send(socket, &end_signal, sizeof(end_signal), 0) < 0) {
        perror("[ERREUR] Erreur lors de l'envoi du signal de fin de fichier");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(file);
    printf("[INFO] Envoi du fichier %s terminé avec succès.\n", filename);
    return 0;
}


int handle_authentication(const char *msg, int client_socket) {
    char username[50], password[50];
    sscanf(msg, "LOGIN:%49[^:]:%49s", username, password);

    // Calculer le hachage du mot de passe reçu
    unsigned char received_hash[32];
    calculate_sha256((unsigned char *)password, strlen(password), received_hash);

    // Stocker un hachage pour le mot de passe admin ("password")
    unsigned char expected_hash[32];
    calculate_sha256((unsigned char *)"password", strlen("password"), expected_hash);

    // Comparer les deux hachages
    if (memcmp(received_hash, expected_hash, 32) == 0) {
	    printf("[INFO] Authentification reussie pour l'utilisateur : %s\n", username);
	    const char *success_response = "AUTH_SUCCESS\n";
	    send(client_socket, success_response, strlen(success_response), 0);
	    printf("[DEBUG] Reponse AUTH_SUCCESS envoyee au client\n");
     } else {
	    fprintf(stderr, "[ERREUR] Echec de l'authentification pour l'utilisateur : %s\n", username);
	    const char *fail_response = "AUTH_FAIL\n";
	    send(client_socket, fail_response, strlen(fail_response), 0);
	    printf("[DEBUG] Reponse AUTH_FAIL envoyee au client\n");
	}
}
