/*
 * A basic example was taken from
 * http://codereview.stackexchange.com/questions/108600/complete-async-openssl-example
 *
 * Compilation:
 * gcc richman2.c -lcrypto -lssl -lsodium -o richman_client
 */
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

const char* hostname = "server_hostname"; /* hostname, like google.com */
const char* ip_address = "server_ip_address"; /* x.x.x.x */
#define PORT 4446 /* port on your server */

const char server_key_str[] = "SERVER_KEY";
const char client_key_str[] = "CLIENT_KEY";
const char* PREFERRED_CIPHERS = "RSA:HIGH";

char server_pk[32] = { 0 };
char client_pk[32] = { 0 };
char client_sk[32] = { 0 };
char shared_secret[32] = { 0 };

char server_key[32] = { 0 };
char client_key[32] = { 0 };
char nonce[8] = { 0 };
char nonce_out[8] = { 0 };

char accumulator[4096] = { 0 };
unsigned int read_marker = 0;

char msgbuffer[4096] = { 0 };
int msgbuf_len = 0;

char decmsg[4096];


typedef enum
{
    CONTINUE,
    BREAK,
    NEITHER
} ACTION;

typedef enum
{
    NOTHING,
    CURVE25519_PK_RECEIVED,
    KEY_NEGOTIATED,
    MESSAGE_IS_BEING_WRITTEN
} STATUS;

STATUS currentStatus = NOTHING;

ACTION ssl_connect(SSL* ssl, int* wants_tcp_write, int* connecting)
{
    int result = SSL_connect(ssl);

    if (result == 0) {
        long error = ERR_get_error();
        const char* error_str = ERR_error_string(error, NULL);
        printf("[E] Could not SSL_connect: %s\n", error_str);
        return BREAK;
    } else if (result < 0) {
        int ssl_error = SSL_get_error(ssl, result);

        if (ssl_error == SSL_ERROR_WANT_WRITE) {
            *wants_tcp_write = 1;
            return CONTINUE;
        }

        if (ssl_error == SSL_ERROR_WANT_READ) {
            // wants_tcp_read is always 1;
            return CONTINUE;
        }

        long error = ERR_get_error();
        const char* error_string = ERR_error_string(error, NULL);
        printf("[E] Could not SSL_connect %s\n", error_string);
        return BREAK;
    } else {
        *connecting = 0;
        return CONTINUE;
    }

    return NEITHER;
}

ACTION ssl_read(SSL* ssl, int* wants_tcp_write, int* call_ssl_read_instead_of_write) {
    if(currentStatus == MESSAGE_IS_BEING_WRITTEN)
        currentStatus = KEY_NEGOTIATED;

    *call_ssl_read_instead_of_write = 0;

    char buffer[1024];
    int num = SSL_read(ssl, buffer, sizeof(buffer));
    if (num == 0) {
        long error = ERR_get_error();
        const char* error_str = ERR_error_string(error, NULL);
        printf("[E] Could not SSL_read (returned 0): %s\n", error_str);
        return BREAK;
    } else if (num < 0) {
        int ssl_error = SSL_get_error(ssl, num);
        if (ssl_error == SSL_ERROR_WANT_WRITE) {
            *wants_tcp_write = 1;
            *call_ssl_read_instead_of_write = 1;
            return CONTINUE;
        }

        if (ssl_error == SSL_ERROR_WANT_READ) {
            // wants_tcp_read is always 1;
            return CONTINUE;
        }

        long error = ERR_get_error();
        const char* error_string = ERR_error_string(error, NULL);
        printf("[E] Could not SSL_read (returned -1) %s\n", error_string);
        return BREAK;
    } else {
        /* We're starting negotiations */
        if(currentStatus == NOTHING){
            memcpy(accumulator + read_marker, buffer, num);
            read_marker += num;
            if(read_marker >= 34) {
                currentStatus = CURVE25519_PK_RECEIVED;
                return NEITHER;
            }
        } else if(currentStatus == CURVE25519_PK_RECEIVED) {
            return NEITHER;
        } else if(currentStatus == KEY_NEGOTIATED) {
            if(num == 0)
                return NEITHER;

            memcpy(msgbuffer + msgbuf_len, buffer, num);
            msgbuf_len += num;

            while(1) {
                int actual_len = msgbuffer[0] << 8 | msgbuffer[1];

                if(msgbuf_len != 0 && actual_len <= msgbuf_len) {
                    memset(decmsg, 0x00, sizeof(decmsg));
                    int d_len = 1024;
                    if(crypto_aead_chacha20poly1305_decrypt(decmsg, (long long unsigned int*)&d_len, NULL, msgbuffer+2, actual_len, NULL, 0, nonce, server_key) == 0) {
                        nonce[0] += 1; /* Will work only for less than 256 messages */
                        printf("%s", decmsg);
                    } else {
                        printf("[E] Could not decrypt message \n");
                    }

                    memset(decmsg, 0x00, sizeof(decmsg));
                    memcpy(decmsg, msgbuffer + actual_len + 2, msgbuf_len - actual_len - 2);
                    memset(msgbuffer, 0x00, sizeof(msgbuffer));
                    memcpy(msgbuffer, decmsg, msgbuf_len - actual_len - 2);
                    msgbuf_len -= (actual_len + 2);
                    continue;
                }
                break;
            }

            return NEITHER;
        }
    }

    return NEITHER;
}

ACTION ssl_write(SSL* ssl, int* wants_tcp_write, int* call_ssl_write_instead_of_read, int should_start_a_new_write) {
    static char buffer[1024];
    static int to_write = 0;

    if(currentStatus == CURVE25519_PK_RECEIVED) {
        int loop = 0;
        RAND_bytes((unsigned char*)client_sk, sizeof(client_sk));

        client_sk[0] &= 248;
        client_sk[31] &= 127;
        client_sk[31] |= 64;

        crypto_scalarmult_curve25519_base(client_pk, client_sk);

        buffer[0] = 0;
        buffer[1] = sizeof(client_pk);

        memcpy(buffer + 2, client_pk, sizeof(client_pk));
        to_write = sizeof(client_pk) + 2;

        memcpy(server_pk, accumulator + 2, sizeof(server_pk));
        crypto_scalarmult_curve25519(shared_secret, client_sk, server_pk);

        printf("[>] Shared secret: ");
        for(loop = 0; loop < 32; loop++)
            printf("%2hhX", shared_secret[loop]);
        printf("\n");

        memcpy(accumulator, server_pk, sizeof(server_pk));
        memcpy(accumulator + sizeof(server_pk), client_pk, sizeof(client_pk));
        memcpy(accumulator + sizeof(server_pk) + sizeof(client_pk), shared_secret, sizeof(shared_secret));

        crypto_generichash_blake2b(shared_secret, sizeof(shared_secret), accumulator,
              sizeof(client_pk) + sizeof(server_pk) + sizeof(shared_secret), NULL, 0);

        crypto_generichash_blake2b_state state1;
        crypto_generichash_blake2b_init(&state1, server_key_str, 10, 32);
        crypto_generichash_blake2b_update(&state1, shared_secret, 32);
        crypto_generichash_blake2b_final(&state1, server_key, 32);

        printf("[>] Server symmetric key: ");
        for(loop = 0; loop < 32; loop++)
            printf("%02hhX", server_key[loop]);
        printf("\n");

        crypto_generichash_blake2b_state state2;

        crypto_generichash_blake2b_init(&state2, client_key_str, 10, 32);
        crypto_generichash_blake2b_update(&state2, shared_secret, 32);
        crypto_generichash_blake2b_final(&state2, client_key, 32);

        printf("[>] Client symmetric key: ");
        for(loop = 0; loop < 32; loop++)
            printf("%02hhX", client_key[loop]);
        printf("\n");

        currentStatus = KEY_NEGOTIATED;
    } else if(currentStatus == KEY_NEGOTIATED){
        char message[1024];
        unsigned long long ciphertext_len = 0;
        memset(message, 0x00, sizeof(message));
        memset(buffer, 0x00, sizeof(buffer));
        fgets(message, sizeof(message), stdin);
        ciphertext_len = strlen(message) + 16;

        if(crypto_aead_chacha20poly1305_encrypt(buffer+2, &ciphertext_len, message,
              strlen(message), NULL, 0, NULL, nonce_out, client_key) == 0)
        {
            nonce_out[0] += 1;
            buffer[0] = (ciphertext_len >> 8) & 0xff;
            buffer[1] = ciphertext_len & 0xff;

            to_write = ciphertext_len + 2;
            currentStatus = MESSAGE_IS_BEING_WRITTEN;
        } else {
            printf("[E] Could not encrypt the message \n");
        }
    }

    if (!*call_ssl_write_instead_of_read && !to_write && should_start_a_new_write) {
        //to_write = 1024;
        printf("[~] Decided to write %d bytes \n", to_write);
    }

    if (*call_ssl_write_instead_of_read && (!to_write || !buffer)) {
        printf("[~] SSL should not have requested a write from a read if no data was waiting to be written\n");
        return BREAK;
    }

    *call_ssl_write_instead_of_read = 0;

    if (!to_write)
    {
        if(currentStatus == MESSAGE_IS_BEING_WRITTEN)
        currentStatus = KEY_NEGOTIATED;
        return NEITHER;
    }

    int num = SSL_write(ssl, buffer, to_write);
    if (num == 0) {
        long error = ERR_get_error();
        const char* error_str = ERR_error_string(error, NULL);
        printf("[E] Could not SSL_write (returned 0): %s\n", error_str);
        return BREAK;
    } else if (num < 0) {
        int ssl_error = SSL_get_error(ssl, num);
        if (ssl_error == SSL_ERROR_WANT_WRITE) {
                *wants_tcp_write = 1;
                return CONTINUE;
        }

        if (ssl_error == SSL_ERROR_WANT_READ) {
            *call_ssl_write_instead_of_read = 1;
            return CONTINUE;
        }

        long error = ERR_get_error();
        const char* error_string = ERR_error_string(error, NULL);
        printf("[E] Could not SSL_write (returned -1): %s\n", error_string);
        return BREAK;
    } else {
        if (to_write < num) {
            *wants_tcp_write = 1;
        } else {
            *wants_tcp_write = 0;
        }
        to_write -= num;
    }

    return NEITHER;
}

int main(int argc, char** argv) {
    int port = PORT;

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (!ssl_ctx) {
        printf("[E] Could not SSL_CTX_new\n");
        return 1;
    }

    int sockfd = 0;
    /* Never do so in your production! */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        printf("[E] Could not create socket \n");
        return 1;
    }


    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        printf("[E] Could not SSL_new \n");
        return 1;
    }

    SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    SSL_set_tlsext_host_name(ssl, hostname);

    // Set the socket to be non blocking.
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK)) {
        printf("[E] Could not fcntl \n");
        close(sockfd);
        return 1;
    }

    int one = 1;
    if (setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &one, sizeof(one))) {
        printf("[E] Could not setsockopt \n");
        close(sockfd);
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_aton(ip_address, &addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)(&addr), sizeof(addr)) && errno != EINPROGRESS) {
        printf("[E] Could not connect \n");
        return 1;
    }

    if (!SSL_set_fd(ssl, sockfd)) {
        close(sockfd);
        printf("[E] Could not SSL_set_fd \n");
        return 1;
    }

    int connecting = 1;
    SSL_set_connect_state(ssl);

    fd_set read_fds, write_fds;
    int wants_tcp_read = 1, wants_tcp_write = 1;
    int call_ssl_read_instead_of_write = 0;
    int call_ssl_write_instead_of_read = 0;

    for (;;) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        if (wants_tcp_read) {
            FD_SET(sockfd, &read_fds);
        }

        if (wants_tcp_write) {
            FD_SET(sockfd, &write_fds);
        }

        struct timeval timeout = { 1, 0 };

        if (select(sockfd + 1, &read_fds, &write_fds, NULL, &timeout)) {
            if (FD_ISSET(sockfd, &read_fds)) {
                if (connecting) {
                    ACTION action = ssl_connect(ssl, &wants_tcp_write, &connecting);
                    if (action == CONTINUE) {
                        continue;
                    } else if (action == BREAK) {
                        break;
                    }
                } else {
                    ACTION action;
                    if (call_ssl_write_instead_of_read) {
                        action = ssl_write(ssl, &wants_tcp_write, &call_ssl_write_instead_of_read, 0);
                    } else {
                        action = ssl_read(ssl, &wants_tcp_write, &call_ssl_read_instead_of_write);
                    }

                    if (action == CONTINUE) {
                        continue;
                    } else if (action == BREAK) {
                        break;
                    }
                }
            }

            if (FD_ISSET(sockfd, &write_fds)) {
                if (connecting) {
                    wants_tcp_write = 0;

                    ACTION action = ssl_connect(ssl, &wants_tcp_write, &connecting);
                    if (action == CONTINUE) {
                        continue;
                    } else if (action == BREAK) {
                        break;
                    }
                } else {
                    ACTION action;
                    if (call_ssl_read_instead_of_write) {
                        action = ssl_read(ssl, &wants_tcp_write, &call_ssl_read_instead_of_write);
                    } else {
                        action = ssl_write(ssl, &wants_tcp_write, &call_ssl_write_instead_of_read, 0);
                    }

                    if (action == CONTINUE) {
                        continue;
                    } else if (action == BREAK) {
                        break;
                    }
                }
            }
        } else if (!connecting && !call_ssl_write_instead_of_read) {
            ACTION action = ssl_write(ssl, &wants_tcp_write, &call_ssl_write_instead_of_read, 1);
            if (action == CONTINUE) {
                continue;
            } else if (action == BREAK) {
                break;
            }
        }
    }

    SSL_CTX_free(ssl_ctx);

    return 0;
}
