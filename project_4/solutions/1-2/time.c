#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

char secret[0x10];

int main()
{
    srand(time(0));
    for (int i = 0; i < 0x10; i++) {
        secret[i] = 48 + (rand() % (126 - 47) + 1);
    }
    printf("%s\n", secret);

    return 0;
}
