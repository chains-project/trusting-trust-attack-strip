#include <stdio.h>
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        fprintf(stderr, "fake_strip: would strip %s\n", argv[i]);
    }
    return 0;
}