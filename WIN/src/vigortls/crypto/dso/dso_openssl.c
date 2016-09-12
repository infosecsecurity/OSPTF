/* Kurt Cancemi places this file in the public domain */

#include <openssl/dso.h>

static DSO_METHOD dso_meth_null = {
    .name = "NULL shared library method"
};

DSO_METHOD *DSO_METHOD_null(void)
{
    return (&dso_meth_null);
}

DSO_METHOD *DSO_METHOD_openssl(void)
{
    return (DSO_METHOD_null());
}
