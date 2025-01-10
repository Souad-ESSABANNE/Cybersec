#include <stdio.h>
#include <string.h>
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <ctype.h>
#include <openssl/rand.h> // Pour RAND_bytes

unsigned char MY_AES_KEY[32] = "mysecurekey1234567890abcdef";
unsigned char AES_IV[16] = "1234567890abcdef";

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

void encrypt_data(const char *input, char *output, int *output_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("[ERREUR] Impossible de créer le contexte de chiffrement");
        *output_len = -1;
        return;
    }

    const unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv)); // Génération aléatoire de l'IV

    // Copier l'IV au début de la sortie
    memcpy(output, iv, sizeof(iv));
    int offset = sizeof(iv);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        perror("[ERREUR] Erreur lors de l'initialisation du chiffrement");
        *output_len = -1;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, (unsigned char *)(output + offset), &len, (unsigned char *)input, strlen(input)) != 1) {
        perror("[ERREUR] Erreur lors de la mise à jour du chiffrement");
        *output_len = -1;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *output_len = len + offset;

    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)(output + offset + len), &len) != 1) {
        perror("[ERREUR] Erreur lors de la finalisation du chiffrement");
        *output_len = -1;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *output_len += len;

    EVP_CIPHER_CTX_free(ctx);
}



int decrypt_data(const char *input, int input_len, char *output) {
    if (input_len <= 16) {
        fprintf(stderr, "[ERREUR] Les données sont trop courtes pour contenir un IV et des données chiffrées.\n");
        return -1;
    }

    // Extraire l'IV
    unsigned char iv[16];
    memcpy(iv, input, 16); // Les 16 premiers octets sont l'IV

    printf("[DEBUG] IV extrait (hex) : ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    // Les données chiffrées commencent après l'IV
    const unsigned char *encrypted_data = (unsigned char *)(input + 16);
    int encrypted_len = input_len - 16;

    // Préparer le contexte de déchiffrement
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[ERREUR] Impossible de créer le contexte de déchiffrement.\n");
        return -1;
    }

    const unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "[ERREUR] Erreur lors de l'initialisation du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    int plaintext_len = 0;
    unsigned char decrypted_data[1024]; // Tampon pour les données déchiffrées

    // Déchiffrer les données
    if (EVP_DecryptUpdate(ctx, (unsigned char *)output, &len, encrypted_data, encrypted_len) != 1) {
        fprintf(stderr, "[ERREUR] Erreur lors de la mise à jour du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finaliser le déchiffrement
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        fprintf(stderr, "[ERREUR] Erreur lors de la finalisation du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    // Ajouter un caractère de fin pour en faire une chaîne valide
    output[plaintext_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);

    printf("[INFO] Données déchiffrées avec succès.\n");
    return plaintext_len;
}
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



int validate_filename(const char *filename) {
    if (strlen(filename) > 255) {
        fprintf(stderr, "[ERREUR] Nom de fichier trop long.\n");
        return 0;
    }

    for (size_t i = 0; i < strlen(filename); i++) {
        if (!isalnum(filename[i]) && filename[i] != '.' && filename[i] != '_') {
            fprintf(stderr, "[ERREUR] Nom de fichier invalide : %s\n", filename);
            return 0;
        }
    }

    return 1; // Nom de fichier valide
}
