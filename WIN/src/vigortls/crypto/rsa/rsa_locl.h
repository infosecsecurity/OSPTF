extern int int_rsa_verify(int dtype, const uint8_t *m, unsigned int m_len,
                          uint8_t *rm, size_t *prm_len,
                          const uint8_t *sigbuf, size_t siglen,
                          RSA *rsa);
