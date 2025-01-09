#ifndef SERVER_H
#define SERVER_H

/* Démarre le serveur sur un port donné */
int startserver(int port);

/* Arrête le serveur */
int stopserver();

/* Lit un message envoyé par le client */
int getmsg(char msg_read[1024]);

/* Sauvegarde un fichier reçu */
int save_uploaded_file(const char *filename, const char *data);

/* Envoie un fichier au client */
int send_file_to_client(int socket, const char *filename);

/* Génère une liste des fichiers stockés */
int list_files(char *response);
int handle_authentication(const char *msg, int client_socket);
#endif // SERVER_H
