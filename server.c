#include "final.h"
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8888
#define MAX 1024
int new_socket;
volatile int stop_flag = 0;  // Shared flag to signal threads to stop

void *receive_messages(void *arg) {
    char buffer[MAX];
    u8* aes_key = (u8*)arg;
    int valread;
    u8 counter[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    u8 expkey[176] = {0};
    AES_128_Key_Expansion(aes_key,expkey);

    while (1) {
        memset(buffer, 0, MAX);
        // Read message from client
        valread = read(new_socket, buffer, MAX);
        if (valread <= 0) {
            printf("Client disconnected.\n");
            stop_flag = 1;
            break;
        }
        u8 * secure_message = aes_gcm_verify_and_decrypt(expkey,counter,buffer);
        printf("%s", secure_message);
        free(secure_message);
    }
    pthread_exit(NULL);
}

void *send_messages(void *arg) {
    char message[MAX];
    u8* aes_key = (u8*)arg;
    char *ad = "From IP 192.168.108.59 :";
    /*char *client_ip = FDtoIP(new_socket);
    size_t len1 = strlen(client_ip);
    size_t len2 = strlen(ad);
    char *a_data = (char*)malloc(len1 + len2 + 1);
    snprintf(a_data, len1 + len2 + 1, "%s%s", ad, client_ip);*/
    
    u8 counter[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    u8 expkey[176] = {0};
    AES_128_Key_Expansion(aes_key,expkey);
    int valsend;
    while (!stop_flag) {
        // Get server message to send to the client
        fgets(message, MAX, stdin);
        
        // On input "bye" disconnect
    	if(memcmp(message,"bye",3)==0)	break;
        
        char* secure_message = aes_gcm_encrypt(expkey,counter,message,strlen(message),ad,strlen(ad));
        // Send message to client
        valsend = send(new_socket, secure_message, strlen(secure_message), 0);
        free(secure_message);
        if (valsend <= 0) break;
    }
    shutdown(new_socket, SHUT_RDWR); //Gracefully shutdown both directions
    pthread_exit(NULL);
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t send_thread, receive_thread;

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define address structure
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    // Accept an incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    printf("====== Welcome ======\n(send 'bye' to leave and bye) \n");
    
    char s_key[65], p_key[129];
    pub_point_generation(s_key, p_key);
    send(new_socket, p_key, strlen(p_key), 0);
    char client_pub_key[129];
    read(new_socket, client_pub_key, 128);
    u8 aes_key[16];
    shared_key_generation(s_key, client_pub_key, aes_key);

    // Create threads for sending and receiving messages
    pthread_create(&send_thread, NULL, send_messages, (void*)aes_key);
    pthread_create(&receive_thread, NULL, receive_messages, (void*)aes_key);

    // Wait for both threads to finish
    pthread_join(send_thread, NULL);
    pthread_join(receive_thread, NULL);

    // Close the socket
    close(new_socket);
    close(server_fd);

    return 0;
}
