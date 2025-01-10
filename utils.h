#ifndef UTILS_H
#define UTILS_H

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

extern unsigned char MY_AES_KEY[AES_KEY_SIZE]; // Déclaration externe
extern unsigned char AES_IV[AES_BLOCK_SIZE];   // Déclaration externe

void encrypt_data(const char *input, char *output, int *output_len);
int decrypt_data(const char *input, int input_len, char *output);
void calculate_sha256(const unsigned char *data, size_t data_len, unsigned char *hash);
int validate_filename(const char *filename);
#endif // UTILS_H
