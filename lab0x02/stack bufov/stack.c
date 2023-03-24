#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    execl("/bin/sh", "sh", "-c", "/bin/sh", (char *) NULL);
}

void vulnerable() {
    char c[70];
    read(0, c, 200);
    printf("You sent %s\n", c);
}


int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setbuf(stdin, NULL);
    printf("Send me your best shot!\n");
    vulnerable();
}
