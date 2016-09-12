#ifndef _HEADER_ENDIAN_H_
#define _HEADER_ENDIAN_H_

#if defined(_WIN32)

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define PDP_ENDIAN 3412

#define BYTE_ORDER LITTLE_ENDIAN

#elif defined __linux__
#include <endian.h>
#else
#include_next <machine/endian.h>
#endif

#endif
