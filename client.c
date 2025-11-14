#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

static void print_ssl_error_and_exit(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static ssize_t write_all(int fd, const void *buf, size_t count) {
    const char *p = buf;
    size_t left = count;
    while (left > 0) {
        ssize_t written = send(fd, p, left, 0);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        left -= (size_t)written;
        p += written;
    }
    return (ssize_t)count;
}

int main(int argc, char **argv) {
    const char *host = "www.example.com";
    const char *port = "443";

    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = argv[2];

    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s:%s): %s\n", host, port, gai_strerror(rc));
        return EXIT_FAILURE;
    }

    int sockfd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);

    if (sockfd == -1) {
        perror("Unable to connect to remote host");
        return EXIT_FAILURE;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) print_ssl_error_and_exit("Unable to create SSL_CTX");

    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        fprintf(stderr, "Warning: could not set default verify paths (system CA). Certificate verification may fail.\n");
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) print_ssl_error_and_exit("Unable to create SSL object");

    if (!SSL_set_tlsext_host_name(ssl, host)) {
        fprintf(stderr, "Warning: could not set SNI for host %s\n", host);
    }

    if (SSL_set_fd(ssl, sockfd) != 1) {
        print_ssl_error_and_exit("SSL_set_fd failed");
    }

    if (SSL_connect(ssl) != 1) {
        print_ssl_error_and_exit("SSL_connect failed");
    }

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification failed: %ld\n", verify_result);
    }

    char request[512];
    int req_len = snprintf(request, sizeof(request),
                           "GET / HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "User-Agent: simple-c-https-client/1.0\r\n"
                           "Connection: close\r\n"
                           "\r\n",
                           host);
    if (req_len < 0 || (size_t)req_len >= sizeof(request)) {
        fprintf(stderr, "Request buffer overflow or encoding error\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return EXIT_FAILURE;
    }

    int to_write = req_len;
    int written_total = 0;
    while (written_total < to_write) {
        int w = SSL_write(ssl, request + written_total, to_write - written_total);
        if (w <= 0) {
            int err = SSL_get_error(ssl, w);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                continue;
            } else {
                print_ssl_error_and_exit("SSL_write failed");
            }
        }
        written_total += w;
    }

    const size_t BUF_SZ = 4096;
    char *readbuf = malloc(BUF_SZ);
    if (!readbuf) {
        fprintf(stderr, "Out of memory\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return EXIT_FAILURE;
    }

    int bytes;
    while (1) {
        bytes = SSL_read(ssl, readbuf, (int)BUF_SZ);
        if (bytes > 0) {
            size_t left = (size_t)bytes;
            char *p = readbuf;
            while (left > 0) {
                ssize_t w = write(STDOUT_FILENO, p, left);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    perror("write");
                    break;
                }
                left -= (size_t)w;
                p += w;
            }
        } else {
            int err = SSL_get_error(ssl, bytes);
            if (err == SSL_ERROR_ZERO_RETURN) {
                break;
            } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            } else {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }

    free(readbuf);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
