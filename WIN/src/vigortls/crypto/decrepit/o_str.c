/* Kurt Cancemi places this file in the public domain. */

#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

int OPENSSL_strncasecmp(const char *str1, const char *str2, size_t n)
{
    return strncasecmp(str1, str2, n);
}
int OPENSSL_strcasecmp(const char *str1, const char *str2)
{
    return strcasecmp(str1, str2);
}
