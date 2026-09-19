def status(logger):
    logger.info("AES encryption disabled")
    example="EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), 0, key, iv)"
    return example
