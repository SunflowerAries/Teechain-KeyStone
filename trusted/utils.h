#ifndef _UTILS_H_
#define _UTILS_H_

#define streq(s1,s2)    (memcmp((s1),(s2),strlen(s2)) == 0)

#define ULL_MAX ((unsigned long long)(~0LL))

char* ulltostr(unsigned long long value);

#endif /* !_UTILS_H_ */