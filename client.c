#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_ATTEMPTS 3

// AES encryption in CTR mode using EVP
int aes_ctr_encrypt_decrypt(const unsigned char *input, int input_len, unsigned char *output, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, output_len;

    // Initialize the AES-CTR cipher
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, output, &output_len, input, input_len);
    EVP_EncryptFinal_ex(ctx, output + output_len, &len);
    output_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return output_len;
}

void read_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    int bytes_received;

    while (1) {
        // Prompt the client to enter a filename or exit
        printf("Enter the file name to read (or type 'exit' to exit): ");
        fgets(filename, sizeof(filename), stdin);
        filename[strcspn(filename, "\n")] = 0;  // Remove newline character

        // Check if the user wants to exit
        if (strcmp(filename, "exit") == 0) {
            break;
        }

        // Send the filename to the server
        SSL_write(ssl, filename, strlen(filename));

        // Receive the server's response (file content or error)
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("File contents:\n%s\n", buffer);
            break;  // Successfully read the file, exit the loop
        } else {
            printf("Error reading from server. Try another file.\n");
        }
    }
}

void edit_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    char new_content[BUFFER_SIZE];
    int bytes_received;

    // Prompt for filename
    printf("Enter the file name to edit: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;  // Remove newline character

    // Send the filename to the server
    SSL_write(ssl, filename, strlen(filename));

    // Get current content from server
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        if (strstr(buffer, "File not found") == NULL) {
            printf("Current content:\n%s\n", buffer);
            
            // Get new content
            printf("Enter new content: ");
            fgets(new_content, sizeof(new_content), stdin);
            new_content[strcspn(new_content, "\n")] = 0;  // Remove newline character

            // Send new content to server
            SSL_write(ssl, new_content, strlen(new_content));

            // Get server's response
            memset(buffer, 0, BUFFER_SIZE);
            bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                printf("%s\n", buffer);
            }
        } else {
            printf("%s\n", buffer);
        }
    } else {
        printf("Error communicating with server.\n");
    }
}

void upload_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    char file_content[BUFFER_SIZE];
    FILE *file;
    int bytes_received;

    // Prompt for filename
    printf("Enter the file name to upload from clientAS folder: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;  // Remove newline character

    // Check if file exists in client folder
    char file_path[BUFFER_SIZE] = "/home/adham/Documents/Final CW/clientAS/";
    strcat(file_path, filename);
    
    file = fopen(file_path, "r");
    if (file != NULL) {
        // Read file content
        memset(file_content, 0, BUFFER_SIZE);
        size_t bytes_read = fread(file_content, 1, BUFFER_SIZE - 1, file);
        file_content[bytes_read] = '\0';
        fclose(file);

        // Send filename to server
        SSL_write(ssl, filename, strlen(filename));

        // Get server acknowledgment
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0 && strcmp(buffer, "ready") == 0) {
            // Send file content
            SSL_write(ssl, file_content, strlen(file_content));

            // Get upload result
            memset(buffer, 0, BUFFER_SIZE);
            bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                printf("%s\n", buffer);
            }
        } else {
            printf("Server not ready to receive file.\n");
        }
    } else {
        printf("File not found in clientAS folder.\n");
        SSL_write(ssl, "error", strlen("error"));
    }
}

void download_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    FILE *file;
    int bytes_received;

    // Prompt for filename
    printf("Enter the file name to download from serverAS folder: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;  // Remove newline character

    // Send filename to server
    SSL_write(ssl, filename, strlen(filename));

    // Get server response
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        
        if (strstr(buffer, "File not found") == NULL) {
            // Create file in client folder
            char file_path[BUFFER_SIZE] = "/home/adham/Documents/Final CW/clientAS/";
            strcat(file_path, filename);
            
            file = fopen(file_path, "w");
            if (file != NULL) {
                fputs(buffer, file);
                fclose(file);
                printf("File downloaded successfully\n");
            } else {
                printf("Error creating file in clientAS folder\n");
            }
        } else {
            printf("%s\n", buffer);
        }
    } else {
        printf("Error receiving file from server\n");
    }
}

void delete_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Prompt for filename and location
    printf("Enter the file name to delete: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;  // Remove newline character

    printf("Delete from (1: clientAS, 2: serverAS): ");
    char location[2];
    fgets(location, sizeof(location), stdin);
    location[strcspn(location, "\n")] = 0;

    // Send delete request to server (filename:location)
    char request[BUFFER_SIZE];
    sprintf(request, "%s:%s", filename, location);
    SSL_write(ssl, request, strlen(request));

    // Get server response
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("%s\n", buffer);
    } else {
        printf("Error communicating with server\n");
    }
}

void list_files(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Receive the list of files from server
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("\n%s\n", buffer);
    } else {
        printf("Error receiving file list from server.\n");
    }
}

void copy_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Prompt for filename
    printf("Enter the file name to copy: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;  // Remove newline character

    // Send the filename to the server
    SSL_write(ssl, filename, strlen(filename));

    // Get server's response
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("%s\n", buffer);
    } else {
        printf("Error communicating with server.\n");
    }
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};
    char email[BUFFER_SIZE], password[BUFFER_SIZE], role[BUFFER_SIZE];
    unsigned char key[16] = "0123456789abcdef";  // Example AES key
    unsigned char iv[EVP_MAX_BLOCK_LENGTH] = {0};  // Initialization vector

    // Initialize SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed!");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        perror("SSL connect failed!");
        exit(EXIT_FAILURE);
    }

    int authenticated = 0;

    int attempts = 0;
    while (attempts < MAX_ATTEMPTS) {
        // Get email from user
        printf("Email Required: ");
        fgets(email, sizeof(email), stdin);
        email[strcspn(email, "\n")] = 0;  // Remove newline character

        // Get password from user
        printf("Password Required: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = 0;  // Remove newline character

        // Send email to server
        SSL_write(ssl, email, strlen(email));
        
        // Send password to server
        SSL_write(ssl, password, strlen(password));

        // Get server's response
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server: %s\n", buffer);

            if (strcmp(buffer, "Login successful") == 0) {
                authenticated = 1;
                break;
            } else {
                attempts++;
                if (attempts < MAX_ATTEMPTS) {
                    printf("Authentication failed. Attempts remaining: %d\n", MAX_ATTEMPTS - attempts);
                }
            }
        }
    }

    if (!authenticated) {
        printf("Maximum login attempts exceeded. Exiting...\n");
        SSL_free(ssl);
        close(sock);
        return 0;
    }

    // Receive role from server
    memset(role, 0, BUFFER_SIZE);
    int bytes_received = SSL_read(ssl, role, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        role[bytes_received] = '\0';
        printf("Role: %s\n", role);
    }

  
    while (1) {
        // Receive and display menu from server
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server: %s\n", buffer);
        }
    
        // Ask the user to choose an option (based on role)
        int choice;
        if (strcmp(role, "Top") == 0) {
            printf("Enter a number from 1-9 (9 to exit): ");
        } else if (strcmp(role, "Medium") == 0) {
            printf("Enter a number from 1-6 (6 to exit): ");
        } else if (strcmp(role, "Entry") == 0) {
            printf("Enter a number from 1-4 (4 to exit): ");
        }
    
        scanf("%d", &choice);
    
        // Send the choice to the server if it's not message sending
        sprintf(buffer, "%d", choice);
        SSL_write(ssl, buffer, strlen(buffer));

        if (choice == 1) {
            char message[BUFFER_SIZE];
            printf("Enter your message: ");
            getchar();  // to consume the leftover newline character
            fgets(message, sizeof(message), stdin);  // Take the message input from the user
            message[strcspn(message, "\n")] = '\0';  // Remove newline character from the message
            SSL_write(ssl, message, strlen(message));
        }
        else if (choice == 2) {
            list_files(ssl);
            continue;
        }
        else if (choice == 3) {
            getchar();  // Consume the newline character
            read_file(ssl);
            continue;  // Skip the generic response handling
        }
        else if (choice == 4 && strcmp(role, "Top") == 0) {
            getchar();  // Consume the newline character
            edit_file(ssl);
            continue;  // Skip the generic response handling
        }
        else if (choice == 5 && strcmp(role, "Top") == 0) {
            getchar();  // Consume the newline character
            upload_file(ssl);
            continue;  // Skip the generic response handling
        }
        else if (choice == 6 && strcmp(role, "Top") == 0) {
            getchar();  // Consume the newline character
            download_file(ssl);
            continue;  // Skip the generic response handling
        }
        else if (choice == 7 && strcmp(role, "Top") == 0) {
            getchar();  // Consume the newline character
            delete_file(ssl);
            continue;  // Skip the generic response handling
        }
        else if (choice == 8 && strcmp(role, "Top") == 0) {
            getchar();
            copy_file(ssl);
            continue;
        }
        else if (choice == 5 && strcmp(role, "Medium") == 0) {
            getchar();
            copy_file(ssl);
            continue;
        }
    
        // Exit condition based on role
        if ((strcmp(role, "Top") == 0 && choice == 9) || 
            (strcmp(role, "Medium") == 0 && choice == 6) || 
            (strcmp(role, "Entry") == 0 && choice == 4)) {
            printf("Exiting...\n");
            break;  // Break out of the loop if the client chooses to exit
        }
    
        // Handle server's response (e.g., Coming Soon or action completion)
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server: %s\n", buffer);
        }
    }
    
    SSL_free(ssl);
    close(sock);
    return 0;
}
