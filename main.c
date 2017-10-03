#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define INPUT_LEN 10

char message[INPUT_LEN+1];

unsigned long validateChar(unsigned long ch) {
    char allowedChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 .,!?;'\"\0\r\n";
    int retval = 0;
    for (int i = 0; i < sizeof(allowedChars)-1; i++) {
        if (ch == allowedChars[i]) {
            retval = 1;
            break;
        }
    }
    return retval;
}

unsigned long toLower(unsigned long ch) {
    if (ch != (ch & 0xFF)) {
        return ch;
    }
    char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char lower[] = "abcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < 26; i++) {
        if (ch == upper[i]) {
            return lower[i];
        }
    }
    return ch;
}

int readMessage() {
    char buf[INPUT_LEN+1];
    memset(buf, 0, INPUT_LEN+1);
    read(0, buf, INPUT_LEN);
    int acceptMessage = 1;
    for (int i = 0; i < INPUT_LEN; i++) {
        if (!validateChar(buf[i])) {
            acceptMessage = 0;
            break;
        }
    }
    if (acceptMessage) {
        memcpy(message, buf, INPUT_LEN);
        return 1;
    }
    return 0;
}

int main() {
    memset(message, 0, INPUT_LEN+1);
    int flagValid = 1;
    int messageValid = readMessage();
    if (!messageValid) {
        exit(0);
    }

    for (int i = 0; i < INPUT_LEN; i++) {
        if (message[i] != toLower(message[i]) || message[i] != ((5*i) % 26) + 97) {
            exit(0);
        }
    }
    exit(1);

}
