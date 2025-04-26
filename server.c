#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <dirent.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_ATTEMPTS 3
#define MAX_USERS 100


struct User {
    char email[BUFFER_SIZE];
    char password[BUFFER_SIZE];
    char role[BUFFER_SIZE];  // Add this to store the role
};

// Check if the file exists
int file_exists(const char *path) {
    struct stat buffer;
    return (stat(path, &buffer) == 0);  // If the file exists, stat returns 0
}


// Declare the users array
struct User users[MAX_USERS];
int user_count = 0;

// Function to load users from the file
int load_users(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open user file");
        return -1;
    }

    while (fscanf(file, "%s %s %s\n", users[user_count].email, users[user_count].password, users[user_count].role) != EOF) {
        user_count++;
        if (user_count >= MAX_USERS) break;
    }

    fclose(file);
    return 0;
}

// Authentication function to check against the loaded users
int authentication(const char *email, const char *pass, char *role) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(email, users[i].email) == 0 && strcmp(pass, users[i].password) == 0) {
            strcpy(role, users[i].role); 
            return 1;  // Valid user
        }
    }
    return 0;  // Authentication failed
}

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

void handle_read_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char file_content[BUFFER_SIZE];
    FILE *file;
    int bytes_received;

    // Receive filename from the client
    memset(filename, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, filename, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        SSL_write(ssl, "Error receiving filename", strlen("Error receiving filename"));
        return;
    }
    filename[bytes_received] = '\0';

    // Check if the file exists in the first directory
    char file_path_client[BUFFER_SIZE] = "/home/adham/Documents/Final CW/clientAS/";
    strcat(file_path_client, filename);
    if (file_exists(file_path_client)) {
        file = fopen(file_path_client, "r");
        if (file != NULL) {
            // Read the file content
            memset(file_content, 0, BUFFER_SIZE);
            size_t bytes_read = fread(file_content, 1, BUFFER_SIZE - 1, file);
            file_content[bytes_read] = '\0';
            fclose(file);
            SSL_write(ssl, file_content, strlen(file_content));
            return;
        }
    }

    // Check if the file exists in the second directory
    char file_path_server[BUFFER_SIZE] = "/home/adham/Documents/Final CW/serverAS/";
    strcat(file_path_server, filename);
    if (file_exists(file_path_server)) {
        file = fopen(file_path_server, "r");
        if (file != NULL) {
            // Read the file content
            memset(file_content, 0, BUFFER_SIZE);
            size_t bytes_read = fread(file_content, 1, BUFFER_SIZE - 1, file);
            file_content[bytes_read] = '\0';
            fclose(file);
            SSL_write(ssl, file_content, strlen(file_content));
            return;
        }
    }

    // If we get here, the file wasn't found or couldn't be read
    SSL_write(ssl, "File not found or cannot be read", strlen("File not found or cannot be read"));
}

void handle_edit_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char file_content[BUFFER_SIZE];
    char new_content[BUFFER_SIZE];
    FILE *file;
    int bytes_received;

    // Receive filename from the client
    memset(filename, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, filename, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        SSL_write(ssl, "Error receiving filename", strlen("Error receiving filename"));
        return;
    }
    filename[bytes_received] = '\0';

    // Check if the file exists in the first directory
    char file_path_client[BUFFER_SIZE] = "/home/adham/Documents/Final CW/clientAS/";
    strcat(file_path_client, filename);
    char file_path_server[BUFFER_SIZE] = "/home/adham/Documents/Final CW/serverAS/";
    strcat(file_path_server, filename);
    
    char *file_path = NULL;
    if (file_exists(file_path_client)) {
        file_path = file_path_client;
    } else if (file_exists(file_path_server)) {
        file_path = file_path_server;
    }

    if (file_path != NULL) {
        // Read current content
        file = fopen(file_path, "r");
        if (file != NULL) {
            memset(file_content, 0, BUFFER_SIZE);
            size_t bytes_read = fread(file_content, 1, BUFFER_SIZE - 1, file);
            file_content[bytes_read] = '\0';
            fclose(file);
            
            // Send current content to client
            SSL_write(ssl, file_content, strlen(file_content));

            // Receive new content from client
            memset(new_content, 0, BUFFER_SIZE);
            bytes_received = SSL_read(ssl, new_content, BUFFER_SIZE - 1);
            if (bytes_received > 0) {
                new_content[bytes_received] = '\0';
                
                // Write new content to file
                file = fopen(file_path, "w");
                if (file != NULL) {
                    fputs(new_content, file);
                    fclose(file);
                    SSL_write(ssl, "File updated successfully", strlen("File updated successfully"));
                    return;
                }
            }
            SSL_write(ssl, "Error updating file", strlen("Error updating file"));
            return;
        }
    }

    SSL_write(ssl, "File not found or cannot be accessed", strlen("File not found or cannot be accessed"));
}

void handle_upload_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char file_content[BUFFER_SIZE];
    FILE *file;
    int bytes_received;

    // Receive filename from client
    memset(filename, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, filename, BUFFER_SIZE - 1);
    if (bytes_received <= 0 || strcmp(filename, "error") == 0) {
        return;
    }
    filename[bytes_received] = '\0';

    // Create file path in server folder
    char file_path[BUFFER_SIZE] = "/home/adham/Documents/Final CW/serverAS/";
    strcat(file_path, filename);

    // Tell client we're ready to receive
    SSL_write(ssl, "ready", strlen("ready"));

    // Receive file content
    memset(file_content, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, file_content, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        file_content[bytes_received] = '\0';
        
        // Write content to new file
        file = fopen(file_path, "w");
        if (file != NULL) {
            fputs(file_content, file);
            fclose(file);
            SSL_write(ssl, "File uploaded successfully", strlen("File uploaded successfully"));
            return;
        }
    }

    SSL_write(ssl, "Error uploading file", strlen("Error uploading file"));
}

void handle_download_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char file_content[BUFFER_SIZE];
    FILE *file;
    int bytes_received;

    // Receive filename from client
    memset(filename, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, filename, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        SSL_write(ssl, "Error receiving filename", strlen("Error receiving filename"));
        return;
    }
    filename[bytes_received] = '\0';

    // Check if file exists in server folder
    char file_path[BUFFER_SIZE] = "/home/adham/Documents/Final CW/serverAS/";
    strcat(file_path, filename);
    
    file = fopen(file_path, "r");
    if (file != NULL) {
        // Read file content
        memset(file_content, 0, BUFFER_SIZE);
        size_t bytes_read = fread(file_content, 1, BUFFER_SIZE - 1, file);
        file_content[bytes_read] = '\0';
        fclose(file);

        // Send file content to client
        SSL_write(ssl, file_content, strlen(file_content));
    } else {
        SSL_write(ssl, "File not found in serverAS folder", strlen("File not found in serverAS folder"));
    }
}

void handle_delete_file(SSL *ssl) {
    char request[BUFFER_SIZE];
    char filename[BUFFER_SIZE];
    char location[2];
    int bytes_received;

    // Receive delete request from client
    memset(request, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, request, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        SSL_write(ssl, "Error receiving delete request", strlen("Error receiving delete request"));
        return;
    }
    request[bytes_received] = '\0';

    // Parse filename and location
    char *delimiter = strchr(request, ':');
    if (delimiter == NULL) {
        SSL_write(ssl, "Invalid delete request format", strlen("Invalid delete request format"));
        return;
    }

    // Split the request into filename and location
    *delimiter = '\0';
    strcpy(filename, request);
    strcpy(location, delimiter + 1);

    // Create full file path based on location
    char file_path[BUFFER_SIZE];
    if (strcmp(location, "1") == 0) {
        strcpy(file_path, "/home/adham/Documents/Final CW/clientAS/");
    } else if (strcmp(location, "2") == 0) {
        strcpy(file_path, "/home/adham/Documents/Final CW/serverAS/");
    } else {
        SSL_write(ssl, "Invalid location specified", strlen("Invalid location specified"));
        return;
    }
    strcat(file_path, filename);

    // Try to delete the file
    if (remove(file_path) == 0) {
        SSL_write(ssl, "File deleted successfully", strlen("File deleted successfully"));
    } else {
        SSL_write(ssl, "Error deleting file (file may not exist)", strlen("Error deleting file (file may not exist)"));
    }
}

void handle_list_files(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    DIR *d;
    struct dirent *dir;
    
    // List files from both directories
    char *directories[] = {"/home/adham/Documents/Final CW/clientAS/", "/home/adham/Documents/Final CW/serverAS/"};
    memset(buffer, 0, BUFFER_SIZE);
    
    for (int i = 0; i < 2; i++) {
        d = opendir(directories[i]);
        if (d) {
            if (i == 0) {
                strcat(buffer, "Files in clientAS:\n");
            } else {
                strcat(buffer, "\nFiles in serverAS:\n");
            }
            
            while ((dir = readdir(d)) != NULL) {
                if (dir->d_type == DT_REG) {  // Only list regular files
                    strcat(buffer, dir->d_name);
                    strcat(buffer, "\n");
                }
            }
            closedir(d);
        }
    }
    
    SSL_write(ssl, buffer, strlen(buffer));
}

void handle_copy_file(SSL *ssl) {
    char filename[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    char new_filename[BUFFER_SIZE];
    FILE *source_file, *dest_file;
    int bytes_received;

    // Receive filename from client
    memset(filename, 0, BUFFER_SIZE);
    bytes_received = SSL_read(ssl, filename, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        SSL_write(ssl, "Error receiving filename", strlen("Error receiving filename"));
        return;
    }
    filename[bytes_received] = '\0';

    // Check both directories for the file
    char source_path[BUFFER_SIZE];
    int found = 0;
    char *directories[] = {"/home/adham/Documents/Final CW/clientAS/", "/home/adham/Documents/Final CW/serverAS/"};
    
    for (int i = 0; i < 2 && !found; i++) {
        strcpy(source_path, directories[i]);
        strcat(source_path, filename);
        
        if (file_exists(source_path)) {
            found = 1;
            
            // Create new filename with (copyX) suffix
            char *dot = strrchr(filename, '.');
            int copy_num = 1;
            if (dot != NULL) {
                *dot = '\0';  // temporarily remove extension
                do {
                    sprintf(new_filename, "%s(copy%d)%s", filename, copy_num, dot);
                    strcpy(buffer, directories[i]);
                    strcat(buffer, new_filename);
                    copy_num++;
                } while (file_exists(buffer));
                *dot = '.';  // restore the dot
            } else {
                do {
                    sprintf(new_filename, "%s(copy%d)", filename, copy_num);
                    strcpy(buffer, directories[i]);
                    strcat(buffer, new_filename);
                    copy_num++;
                } while (file_exists(buffer));
            }

            // Copy the file
            source_file = fopen(source_path, "r");
            if (source_file == NULL) {
                SSL_write(ssl, "Error opening source file", strlen("Error opening source file"));
                return;
            }

            dest_file = fopen(buffer, "w");
            if (dest_file == NULL) {
                fclose(source_file);
                SSL_write(ssl, "Error creating destination file", strlen("Error creating destination file"));
                return;
            }

            // Copy content
            char ch;
            while ((ch = fgetc(source_file)) != EOF) {
                fputc(ch, dest_file);
            }

            fclose(source_file);
            fclose(dest_file);

            // Send success message
            sprintf(buffer, "File copied successfully as %s", new_filename);
            SSL_write(ssl, buffer, strlen(buffer));
            return;
        }
    }

    SSL_write(ssl, "File not found", strlen("File not found"));
}

void *client_handler(void *arg) {
    SSL *ssl = (SSL *)arg;
    char email[BUFFER_SIZE], password[BUFFER_SIZE], buffer[BUFFER_SIZE], role[BUFFER_SIZE];
    int authenticated = 0;
    int attempt;

    // Receive email
    memset(email, 0, BUFFER_SIZE);
    int bytes_received = SSL_read(ssl, email, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        perror("Failed to receive email");
        SSL_free(ssl);
        return NULL;
    }
    email[bytes_received] = '\0';

    for (attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        // Receive password
        memset(password, 0, BUFFER_SIZE);
        bytes_received = SSL_read(ssl, password, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            perror("Failed to receive password");
            SSL_free(ssl);
            return NULL;
        }
        password[bytes_received] = '\0';

        // Authentication check
        if (authentication(email, password, role)) {
            printf("\n==========Authentication==========\n");
            printf("Attempt #%d\n", attempt);
            printf("Username: %s\n", email);
            printf("Password: %s\n", password);
            printf("Status: Authentication successful\n");
            printf("=================================\n\n");
            SSL_write(ssl, "Login successful", strlen("Login successful"));
            authenticated = 1;
            break;
        } else if (attempt < MAX_ATTEMPTS) {
            printf("\n==========Authentication==========\n");
            printf("Attempt #%d\n", attempt);
            printf("Username: %s\n", email);
            printf("Password: %s\n", password);
            printf("Status: Authentication failed\n");
            printf("=================================\n\n");
            SSL_write(ssl, "Wrong password. Try again.", strlen("Wrong password. Try again."));
        } else {
            printf("\n==========Authentication==========\n");
            printf("Attempt #%d\n", attempt);
            printf("Username: %s\n", email);
            printf("Password: %s\n", password);
            printf("Status: Maximum attempts reached\n");
            printf("=================================\n\n");
            SSL_write(ssl, "Failed Login!", strlen("Failed Login!"));
            SSL_free(ssl);
            return NULL;
        }
    }

    // Send the role to the client
    if (authenticated) {
        SSL_write(ssl, role, strlen(role));

        // Menu loop
        while (1) {
            // Display the menu based on role
            if (strcmp(role, "Top") == 0) {
                SSL_write(ssl, "==========Menu==========\n1. Send a message\n2. List files\n3. Read a file\n4. Edit a file\n5. Upload file from client to server\n6. Download file from server to client\n7. Delete a file\n8. Copy file\n9. Exit", 260);
            } else if (strcmp(role, "Medium") == 0) {
                SSL_write(ssl, "==========Menu==========\n1. Send a message\n2. List files\n3. Read a file\n4. Edit a file\n5. Copy file\n6. Exit", 190);
            } else if (strcmp(role, "Entry") == 0) {
                SSL_write(ssl, "==========Menu==========\n1. Send a message\n2. List files\n3. Read a file\n4. Exit", 130);
            }

            // Receive choice from client
            memset(buffer, 0, BUFFER_SIZE);
            bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes_received <= 0) {
                perror("Failed to receive choice");
                SSL_free(ssl);
                return NULL;
            }

            // Handle menu choice
            int choice = atoi(buffer); // Convert choice to integer
            if (choice == 1) {
                // Receive message from client
                memset(buffer, 0, BUFFER_SIZE);
                bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
                if (bytes_received <= 0) {
                    perror("Failed to receive message");
                    SSL_free(ssl);
                    return NULL;
                }
                buffer[bytes_received] = '\0';

                // Print the message on the server side
                printf("\n==========Client Message==========\n");
                printf("From: %s\n", email);
                printf("Message: %s\n", buffer);
                printf("=================================\n\n");

                // Save message to file
                FILE *msg_file = fopen("/home/adham/Documents/Final CW/serverAS/messages.txt", "a");
                if (msg_file != NULL) {
                    fprintf(msg_file, "%s: %s\n", email, buffer);
                    fclose(msg_file);
                }

                // Optionally, respond back to the client to acknowledge receipt
                const char *response = "Message received and saved";
                SSL_write(ssl, response, strlen(response));
            }
            else if (choice == 2) {
                handle_list_files(ssl);
            }
            else if (choice == 3) {
                handle_read_file(ssl);
            }
            else if (choice == 4) {
                handle_edit_file(ssl);
            }
            else if (choice == 5 && strcmp(role, "Top") == 0) {
                handle_upload_file(ssl);
            }
            else if (choice == 6 && strcmp(role, "Top") == 0) {
                handle_download_file(ssl);
            }
            else if (choice == 7 && strcmp(role, "Top") == 0) {
                handle_delete_file(ssl);
            }
            else if (choice == 8 && strcmp(role, "Top") == 0) {
                handle_copy_file(ssl);
            }
            else if (choice == 5 && strcmp(role, "Medium") == 0) {
                handle_copy_file(ssl);
            }
            else if (choice == 9 || (strcmp(role, "Medium") == 0 && choice == 6) || (strcmp(role, "Entry") == 0 && choice == 4)) {
                SSL_write(ssl, "Goodbye!", strlen("Goodbye!"));
                break;  // Break out of the loop if the client chooses to exit
            }
            else {
                // For other unimplemented actions
                SSL_write(ssl, "Coming Soon...", strlen("Coming Soon..."));
            }
        }
    }

    // Close client connection and free SSL resources, but do not close the server
    SSL_free(ssl);
    return NULL;  
}





// Server main function
int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t tid;

    // Initialize SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    // Load certificate and key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        perror("Error loading SSL certificate or private key");
        exit(EXIT_FAILURE);
    }

    // Load users from the file
    if (load_users("user.txt") != 0) {
        return -1;
    }

    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed!");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed!");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed!");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept client connection and handle with SSL
    while (1) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed!");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        if (SSL_accept(ssl) <= 0) {
            perror("SSL accept failed!");
            SSL_free(ssl);
            continue;
        }

        pthread_create(&tid, NULL, client_handler, (void*)ssl);
        pthread_detach(tid);
    }

    // Cleanup SSL
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
