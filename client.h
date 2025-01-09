/* send message (maximum size: 1024 bytes) */
#ifndef CLIENT_H
#define CLIENT_H

/* Envoie un message au serveur (taille maximale : 1024 octets) */
int sndmsg(char msg[1024], int port);

/* Téléverse un fichier au serveur */
int upload_file(const char *filename, int port);

/* Télécharge un fichier depuis le serveur */
int download_file(const char *filename, int port);

/* Demande la liste des fichiers disponibles sur le serveur */
int request_file_list(int port);

/* Analyse les commandes passées en ligne de commande */
int parse_command(int argc, char *argv[], int port);

int authenticate(const char *username, const char *password, int port);
#endif // CLIENT_Hs
