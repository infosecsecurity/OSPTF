#undef c2l
#define c2l(c, l)                                                             \
    (l = ((unsigned long)(*((c)++))), l |= ((unsigned long)(*((c)++))) << 8L, \
     l |= ((unsigned long)(*((c)++))) << 16L,                                 \
     l |= ((unsigned long)(*((c)++))) << 24L)

/* NOTE - c is not incremented as per c2l */
#undef c2ln
#define c2ln(c, l1, l2, n)                                \
    {                                                     \
        c += n;                                           \
        l1 = l2 = 0;                                      \
        switch (n) {                                      \
            case 8:                                       \
                l2 = ((unsigned long)(*(--(c)))) << 24L;  \
            case 7:                                       \
                l2 |= ((unsigned long)(*(--(c)))) << 16L; \
            case 6:                                       \
                l2 |= ((unsigned long)(*(--(c)))) << 8L;  \
            case 5:                                       \
                l2 |= ((unsigned long)(*(--(c))));        \
            case 4:                                       \
                l1 = ((unsigned long)(*(--(c)))) << 24L;  \
            case 3:                                       \
                l1 |= ((unsigned long)(*(--(c)))) << 16L; \
            case 2:                                       \
                l1 |= ((unsigned long)(*(--(c)))) << 8L;  \
            case 1:                                       \
                l1 |= ((unsigned long)(*(--(c))));        \
        }                                                 \
    }

#undef l2c
#define l2c(l, c)                               \
    (*((c)++) = (uint8_t)(((l)) & 0xff),        \
     *((c)++) = (uint8_t)(((l) >> 8L) & 0xff),  \
     *((c)++) = (uint8_t)(((l) >> 16L) & 0xff), \
     *((c)++) = (uint8_t)(((l) >> 24L) & 0xff))

/* NOTE - c is not incremented as per l2c */
#undef l2cn
#define l2cn(l1, l2, c, n)                                  \
    {                                                       \
        c += n;                                             \
        switch (n) {                                        \
            case 8:                                         \
                *(--(c)) = (uint8_t)(((l2) >> 24L) & 0xff); \
            case 7:                                         \
                *(--(c)) = (uint8_t)(((l2) >> 16L) & 0xff); \
            case 6:                                         \
                *(--(c)) = (uint8_t)(((l2) >> 8L) & 0xff);  \
            case 5:                                         \
                *(--(c)) = (uint8_t)(((l2)) & 0xff);        \
            case 4:                                         \
                *(--(c)) = (uint8_t)(((l1) >> 24L) & 0xff); \
            case 3:                                         \
                *(--(c)) = (uint8_t)(((l1) >> 16L) & 0xff); \
            case 2:                                         \
                *(--(c)) = (uint8_t)(((l1) >> 8L) & 0xff);  \
            case 1:                                         \
                *(--(c)) = (uint8_t)(((l1)) & 0xff);        \
        }                                                   \
    }

/* NOTE - c is not incremented as per n2l */
#define n2ln(c, l1, l2, n)                               \
    {                                                    \
        c += n;                                          \
        l1 = l2 = 0;                                     \
        switch (n) {                                     \
            case 8:                                      \
                l2 = ((unsigned long)(*(--(c))));        \
            case 7:                                      \
                l2 |= ((unsigned long)(*(--(c)))) << 8;  \
            case 6:                                      \
                l2 |= ((unsigned long)(*(--(c)))) << 16; \
            case 5:                                      \
                l2 |= ((unsigned long)(*(--(c)))) << 24; \
            case 4:                                      \
                l1 = ((unsigned long)(*(--(c))));        \
            case 3:                                      \
                l1 |= ((unsigned long)(*(--(c)))) << 8;  \
            case 2:                                      \
                l1 |= ((unsigned long)(*(--(c)))) << 16; \
            case 1:                                      \
                l1 |= ((unsigned long)(*(--(c)))) << 24; \
        }                                                \
    }

/* NOTE - c is not incremented as per l2n */
#define l2nn(l1, l2, c, n)                                 \
    {                                                      \
        c += n;                                            \
        switch (n) {                                       \
            case 8:                                        \
                *(--(c)) = (uint8_t)(((l2)) & 0xff);       \
            case 7:                                        \
                *(--(c)) = (uint8_t)(((l2) >> 8) & 0xff);  \
            case 6:                                        \
                *(--(c)) = (uint8_t)(((l2) >> 16) & 0xff); \
            case 5:                                        \
                *(--(c)) = (uint8_t)(((l2) >> 24) & 0xff); \
            case 4:                                        \
                *(--(c)) = (uint8_t)(((l1)) & 0xff);       \
            case 3:                                        \
                *(--(c)) = (uint8_t)(((l1) >> 8) & 0xff);  \
            case 2:                                        \
                *(--(c)) = (uint8_t)(((l1) >> 16) & 0xff); \
            case 1:                                        \
                *(--(c)) = (uint8_t)(((l1) >> 24) & 0xff); \
        }                                                  \
    }

#undef n2l
#define n2l(c, l)                             \
    (l = ((unsigned long)(*((c)++))) << 24L,  \
     l |= ((unsigned long)(*((c)++))) << 16L, \
     l |= ((unsigned long)(*((c)++))) << 8L, l |= ((unsigned long)(*((c)++))))

#undef n2s
#define n2s(c, l) (l = ((uint32_t)(*((c)++))) << 8L, \
                   l |= ((uint32_t)(*((c)++))))

#undef l2n
#define l2n(l, c)                               \
    (*((c)++) = (uint8_t)(((l) >> 24L) & 0xff), \
     *((c)++) = (uint8_t)(((l) >> 16L) & 0xff), \
     *((c)++) = (uint8_t)(((l) >> 8L) & 0xff),  \
     *((c)++) = (uint8_t)(((l)) & 0xff))
