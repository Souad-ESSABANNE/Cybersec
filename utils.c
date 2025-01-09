#include <stdio.h>
#include <string.h>
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/aes.h>

unsigned char MY_AES_KEY[32] = "mysecurekey1234567890abcdef";
unsigned char AES_IV[16] = "1234567890abcdef";

void encrypt_data(const char *input, char *output, int *output_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Contexte pour le chiffrement
    if (!ctx) {
        perror("Erreur de création du contexte EVP");
        return;
    }

    // Initialiser le contexte avec AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, MY_AES_KEY, AES_IV) != 1) {
        perror("Erreur d'initialisation du chiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len = 0;
    int ciphertext_len = 0;

    // Chiffrer les données
    if (EVP_EncryptUpdate(ctx, (unsigned char *)output, &len, (unsigned char *)input, strlen(input)) != 1) {
        perror("Erreur lors du chiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    // Finaliser le chiffrement
    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        perror("Erreur lors de la finalisation du chiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    *output_len = ciphertext_len; // Longueur des données chiffrées
    EVP_CIPHER_CTX_free(ctx);
}

int decrypt_data(const char *input, int input_len, char *output) {
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Créer un contexte de déchiffrement
    if (!ctx) {
        perror("Erreur de création du contexte EVP");
        return -1;
    }

    // Initialiser le contexte avec AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, MY_AES_KEY, AES_IV) != 1) {
        perror("Erreur d'initialisation du déchiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    int plaintext_len = 0;

    // Déchiffrer les données
    if (EVP_DecryptUpdate(ctx, (unsigned char *)output, &len, (unsigned char *)input, input_len) != 1) {
        perror("Erreur lors du déchiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finaliser le déchiffrement
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        perror("Erreur lors de la finalisation du déchiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    output[plaintext_len] = '\0'; // Terminer la chaîne déchiffrée
    EVP_CIPHER_CTX_free(ctx);

    printf("[DEBUG] Données déchiffrées (hex) : ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", (unsigned char)output[i]);
    }
    printf("\n");

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
