#include <stdio.h>
#include <stdlib.h>

int is_prime(int n) {
    if (n < 2) return 0;
    for (int d = 2; d * d <= n; d++)
        if (n % d == 0) return 0;
    return 1
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 100;
    int first = 1;
    for (int i = 2; i < n; i++)
        if (is_prime(i)) { printf(first ? "%d" : " %d", i); first = 0; }
    printf("\n");
    return 0;
}
