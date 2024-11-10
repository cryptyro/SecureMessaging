#include "final.h"
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8888
#define MAX 1024
#define SERVER_IP "127.0.0.1"
int client_fd;
volatile int stop_flag = 0;  // Shared flag to signal threads to stop

//For error handling
void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}
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
        valread = read(client_fd, buffer, MAX);
        if (valread <= 0) {
            printf("Server disconnected.\n");
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
    char *ad = "From IP 192.168.108.65 :";
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
        valsend = send(client_fd, secure_message, strlen(secure_message), 0);
        free(secure_message);
        if (valsend <= 0) break;
    }
    shutdown(client_fd, SHUT_RDWR); //Gracefully shutdown both directions
    
    pthread_exit(NULL);
}

int main() {
    struct sockaddr_in server_addr;
    pthread_t send_thread, receive_thread;

    // Socket creation
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error("Unable to create socket");

    // Configuring server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to the server
    if(connect(client_fd,(struct sockaddr*)&server_addr,sizeof(server_addr))<0)
        error("Connection failed");
    
    printf("====== Welcome ======\n(send 'bye' to leave) \n");

    char s_key[65], p_key[129];
    pub_point_generation(s_key, p_key);
    char server_pub_key[129];
    read(client_fd, server_pub_key, 128);
    send(client_fd, p_key, strlen(p_key), 0);
    u8 aes_key[16];
    shared_key_generation(s_key, server_pub_key, aes_key);

    // Create threads for sending and receiving messages
    pthread_create(&send_thread, NULL, send_messages, (void*)aes_key);
    pthread_create(&receive_thread, NULL, receive_messages, (void*)aes_key);

    // Wait for both threads to finish
    pthread_join(send_thread, NULL);
    pthread_join(receive_thread, NULL);

    // Close the socket
    close(client_fd);
    printf("Disconnected from server\n");
    return 0;
}
