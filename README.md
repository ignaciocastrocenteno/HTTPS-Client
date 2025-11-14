# HTTPS-Client
Creating a HTTPS Client and understanding how the TLS and HTTP protocols work along to generate a secure communication via the web, using SSL certificates.

## Project Overview
This project implements a minimal yet fully functional HTTPS client written in C, using:
* POSIX sockets for TCP communication
* OpenSSL for TLS encryption
* Manual byte-order utilities (htons, htonl)
* Memory-safe stack allocations
* Error-handling best practices

It demonstrates how to:
1) Create a TCP connection to a server
2) Upgrade that connection to TLS using OpenSSL
3) Send an HTTPS request
4) Read and print the server’s TLS-encrypted response
5) Cleanly release all allocated resources

The purpose of this project is to learn and to understand the internals of HTTPS, the handshake process, SSL structures, and secure socket programming.

## Learnings From the Project
By completing this client, you gain a strong understanding of:

* How low-level socket programming works
* How TLS is layered on top of TCP
* How the OpenSSL API manages contexts, sessions, and encrypted streams
* How byte order conversion works (htonl, htons)
* How clients send HTTP requests manually
* How servers respond and how to parse the response
* Why security must always include cleanup (to prevent leaks)
* Why error handling is critical in C
* How to avoid segmentation faults and invalid memory accesses
* How to structure a minimal program while preserving maintainability

## Good Practices Implemented
✔️ Clean Code
* Clear variable names (sockfd, ctx, ssl, buffer).
* High cohesion: the function strictly focuses on the HTTPS request process.
* Comments in English explaining why something is done, not only what.

✔️ KISS (Keep It Simple, Stupid)
* The implementation intentionally avoids unnecessary abstractions:
* One main function
* Straightforward execution flow
* Direct use of OpenSSL APIs
* This makes it easier to read and reason about for newcomers to TLS networking.

✔️ YAGNI (You Aren’t Gonna Need It)
* No unnecessary wrappers, no premature abstractions.
* The client only implements the minimum required logic:
* One request
* One response read
* One TLS context
* Nothing beyond what is strictly necessary for the goal.

✔️ Efficient Memory Use
* No malloc() calls → No risk of heap leaks
* All memory structures are stack-allocated
* OpenSSL objects are properly freed using:
* SSL_free()
* SSL_CTX_free()
* close()
* This makes it inherently safe against memory fragmentation or leaks.

✔️ Pointer Safety
* Pointers are only used when required by system and OpenSSL APIs.
* Never dereferenced before null-checking in future-proof version.
* No pointer arithmetic, reducing complexity and risk.

✔️ Robust Error Handling
The improved version of the program handles errors for:
* socket()
* connect()
* SSL_CTX_new()
* SSL_new()
* SSL_connect()
* SSL_write()
* SSL_read()

All of this prevents undefined behavior and gives clear feedback to users.

## Time Complexity
Although this is a network-bound application where latency dominates runtime, the algorithmic time complexity of the client can be summarized as follows:

1) `O(1)` from program perspective
(resolution time is external, but input size is constant).

2) `O(k)`
Where k is the number of handshake steps (constant for typical TLS versions).

3) If the response is **N bytes**, the reading loop costs:
    ```bash
    O(N / BUFFER_SIZE)
    ```
4) Overall Complexity
    ```bash
    O(n)
    ```
    Where N is the size of the response body received from the server.

## Libraries Used for the Project
* Standard C Library
    * stdio.h – printing, debugging output
    * stdlib.h – memory allocation, exit codes
    * string.h – string manipulation functions
    * unistd.h – close() for sockets
    * errno.h – standardized error reporting

* POSIX Networking
    * sys/socket.h – socket creation and communication
    * netdb.h – DNS resolution (getaddrinfo)
    * arpa/inet.h – host/network byte order utilities
    * netinet/in.h – IPv4/IPv6 address structures

* OpenSSL
Used for all TLS/SSL features:
    * SSL_CTX_new – create TLS context
    * SSL_new – create session
    * SSL_set_fd – bind to socket
    * SSL_connect – handshake
    * SSL_write/SSL_read – encrypted communication

## Library Function Manual
I've used the following bash commands to access the standard manual of the corresponding functions that I've used in project's implementation, since there're a lot of parameter types which different and its difficult to remember all of those by memorizing:
```bash
man socket
man connect
man sockaddr
man htons
man SSL_CTX_new
man SSL_new
man SSL_set_fd
man SSL_connect
man SSL_write
man SSL_read
```
## How to compile the code
```bash
gcc -Wall -Wextra -std=c11 -o client client.c -lssl -lcrypto
```

## How to check there are not memory leaks (using valgrind library)
```bash
valgrind --leak-check=full --show-leak-kinds=all ./client www.google.com 443
```

# License
This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

By using, modifying, or distributing this software, you agree to the terms defined in the GPL-3.0 license. In summary:

- You are free to **run**, **study**, **modify**, and **share** the software.
- If you distribute modified versions of the program, the result must also be licensed under **GPL-3.0**, ensuring the same freedoms for users.
- Any redistributed version—modified or unmodified—must include a copy of the license and appropriate copyright notices.
- No warranty is provided, as explicitly described in the license.

For the full legal text, refer to the official GPL-3.0 license:

**https://www.gnu.org/licenses/gpl-3.0.en.html**

