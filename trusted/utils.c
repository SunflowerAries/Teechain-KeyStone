#include "utils.h"
#include "malloc.h"
#include "string.h"

char* ulltostr(unsigned long long value) {
    char buf[64], *p;

    p = buf + 63;
    do {
        *p-- = '0' + (value % 10);
        value /= 10;
    } while (value);
    p++;
    int len = 64 - (p - buf);
    char *s = (char *)malloc(sizeof(char) * (len + 1));
    memcpy(s, p, len);
    s[len] = '\0';
    return s;
}