#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

//#define MAX_LINE 512
#define MAX_EMAIL 128
#define MAX_HASH 65 
//#define MAX_PASS 128
//#define MAX_USERS 1000

void sha256_string(const char *input, char *output_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
}

//int email_already_hashed(const char *email, char hashed_emails[][MAX_EMAIL], int count) {  // [NEW FUNCTION]
//    for (int i = 0; i < count; i++) {
//        if (strcmp(email, hashed_emails[i]) == 0) {
//            return 1;
//        }
//    }
//    return 0;
//}

int main() {
    FILE *input = fopen("user.txt", "r");
    FILE *output = fopen("user_hashed.txt", "a");

    if (!input || !output) {
        perror("Error opening files");
        return 1;
    }

    char email[MAX_EMAIL];
    char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    const char *hardcoded_password = "farida";  // 🔐 Hardcoded password
    printf("Enter email: ");
    scanf("%s", email);
    sha256_string(hardcoded_password, hash_hex);
    fprintf(output, "%s %s\n", email, hash_hex);
    // [NEW BLOCK] Load already hashed emails
    //char hashed_emails[MAX_USERS][MAX_EMAIL];
    //int hashed_count = 0;
    //char email[MAX_EMAIL], password[MAX_PASS];

    // Rewind and read existing hashes
    //rewind(output);
    //while (fscanf(output, "%s %*s", email) == 1) {
    //    strncpy(hashed_emails[hashed_count++], email, MAX_EMAIL);
    //}

    //while (fscanf(input, "%s %s", email, password) == 2) {
    //    sha256_string(password, hash_hex);
    //    fprintf(output, "%s %s\n", email, hash_hex);
    //}
    // Rewind user.txt and process
    //rewind(input);
    //char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    //while (fscanf(input, "%s %s", email, password) == 2) {
    //    if (!email_already_hashed(email, hashed_emails, hashed_count)) {
    //        sha256_string(password, hash_hex);
    //        fprintf(output, "%s %s\n", email, hash_hex);
    //        strncpy(hashed_emails[hashed_count++], email, MAX_EMAIL);
     //   }
    //}
    //if (fscanf(input, "%s %s", email, password) == 2) {
    //    sha256_string(password, hash_hex);           // 🆕 ADDED hash calculation
    //    fprintf(output, "%s %s\n", email, hash_hex); // 🆕 ADDED append to hash file
    //}
    //fclose(input);
    fclose(output);

    printf("Done! Hashed user list saved to user_hashed.txt\n");
    return 0;
}
