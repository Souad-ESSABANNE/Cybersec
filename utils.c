#include <stdio.h>
#include <string.h>
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/aes.h>


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

void decrypt_data(const char *input, int input_len, char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Contexte pour le déchiffrement
    if (!ctx) {
        perror("Erreur de création du contexte EVP");
        return;
    }

    // Initialiser le contexte avec AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, MY_AES_KEY, AES_IV) != 1){
        perror("Erreur d'initialisation du déchiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len = 0;
    int plaintext_len = 0;

    // Déchiffrer les données
    if (EVP_DecryptUpdate(ctx, (unsigned char *)output, &len, (unsigned char *)input, input_len) != 1) {
        perror("Erreur lors du déchiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len = len;

    // Finaliser le déchiffrement
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)output + len, &len) != 1) {
        perror("Erreur lors de la finalisation du déchiffrement");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += len;

    output[plaintext_len] = '\0'; // Terminer la chaîne déchiffrée
    EVP_CIPHER_CTX_free(ctx);
}
