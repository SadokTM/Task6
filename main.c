#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>

#define MAX_SIZE (10 * 1024 * 1024)

int parse_args(int argc, char *argv[], char **ip, int *port) {
    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-server") && i + 1 < argc) {
            *ip = argv[++i];
        } else if (!strcmp(argv[i], "-port") && i + 1 < argc) {
            *port = atoi(argv[++i]);
        }
    }
    return (*ip != NULL && *port != 0);
}

void decipher(unsigned int *v, const unsigned int *k) {
    unsigned int y = v[0], z = v[1];
    unsigned int sum = 0xC6EF3720, delta = 0x9E3779B9;
    int n;
    for (n = 0; n < 32; n++) {
        z -= ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3]);
        y -= ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = y;
    v[1] = z;
}

int is_mostly_ascii(unsigned char *data, size_t len) {
    size_t i;
    size_t count = 0;
    for (i = 0; i < len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            count++;
        }
    }
    return (count * 10 > len * 7);  // tilsvarer > 70 %
}

size_t remove_pkcs5_padding(unsigned char *data, size_t len) {
    unsigned char pad;
    size_t i;
    if (len == 0) return len;
    pad = data[len - 1];
    if (pad >= 1 && pad <= 8 && pad <= len) {
        for (i = len - pad; i < len; i++) {
            if (data[i] != pad) {
                return len; // invalid padding
            }
        }
        return len - pad;
    }
    return len;
}

size_t find_http_body_offset(unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i + 3 < len; i++) {
        if (data[i] == 0x0D && data[i + 1] == 0x0A && data[i + 2] == 0x0D && data[i + 3] == 0x0A) {
            return i + 4;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    char *server_ip = NULL;
    int port = 0;

    if (!parse_args(argc, argv, &server_ip, &port)) {
        fprintf(stderr, "Usage: %s -server <ip> -port <port>\n", argv[0]);
        return 1;
    }

    {
        int sock;
        struct sockaddr_in addr;
        unsigned char *buffer;
        size_t total;
        int n;
        FILE *f;
        int i, j;
        size_t offset;
        unsigned char *decrypted;
        unsigned int key[4];
        unsigned int test_key[4];
        int found;
        size_t outlen;

        sock = socket(AF_INET, SOCK_STREAM, 0);
        buffer = malloc(MAX_SIZE);
        total = 0;

        if (sock < 0 || buffer == NULL) {
            perror("socket/malloc");
            return 1;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, server_ip, &addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("connect");
            return 1;
        }

        while ((n = recv(sock, buffer + total, MAX_SIZE - total, 0)) > 0) {
            total += n;
        }
        close(sock);

        printf("Received %lu bytes\n", (unsigned long)total);
        for (i = 0; i < 16 && i < (int)total; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");

        f = fopen("raw_received.bin", "wb");
        if (f) {
            fwrite(buffer, 1, total, f);
            fclose(f);
            printf("Dumped raw data to raw_received.bin\n");
        } else {
            perror("fopen raw dump");
        }

        offset = find_http_body_offset(buffer, total);
        if (offset == 0 || (total - offset) % 8 != 0) {
            fprintf(stderr, "Invalid TEA block size or HTTP offset.\n");
            return 1;
        }

        decrypted = malloc(total - offset);
        if (!decrypted) {
            perror("malloc decrypted");
            return 1;
        }

        found = 0;
        for (i = 0; i < 256 && !found; i++) {
            for (j = 0; j < 4; j++) {
                test_key[j] = (i << 24) | (i << 16) | (i << 8) | i;
            }
            for (j = 0; j < (int)(total - offset); j += 8) {
                unsigned int block[2];
                memcpy(block, buffer + offset + j, 8);
                decipher(block, test_key);
                memcpy(decrypted + j, block, 8);
            }
            if (is_mostly_ascii(decrypted, total - offset)) {
                memcpy(key, test_key, sizeof(key));
                found = 1;
            }
        }

        if (!found) {
            fprintf(stderr, "Failed to decrypt with single-byte key.\n");
            return 1;
        }

        printf("Key found: %02X\n", key[0] & 0xFF);

        outlen = remove_pkcs5_padding(decrypted, total - offset);
        f = fopen("decrypted_output.txt", "wb");
        if (f) {
            fwrite(decrypted, 1, outlen, f);
            fclose(f);
            printf("Decrypted output saved to decrypted_output.txt\n");
        } else {
            perror("fopen decrypted");
            return 1;
        }

        free(decrypted);
        free(buffer);
    }

    return 0;
}

