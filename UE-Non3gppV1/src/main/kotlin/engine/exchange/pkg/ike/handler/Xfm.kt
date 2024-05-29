package engine.exchange.pkg.ike.handler

import engine.exchange.pkg.ike.message.AuthenticationAlgorithm
import engine.exchange.pkg.ike.message.EncryptionAlgorithm

enum class XFRMEncryptionAlgorithmType(val value: UInt) {
    DES(EncryptionAlgorithm.ENCR_DES.value),
    DES3(EncryptionAlgorithm.ENCR_3DES.value),
    CAST(EncryptionAlgorithm.ENCR_CAST.value),
    BLOWFISH(EncryptionAlgorithm.ENCR_BLOWFISH.value),
    NULL(EncryptionAlgorithm.ENCR_NULL.value),
    AES_CBC(EncryptionAlgorithm.ENCR_AES_CBC.value),
    AES_CTR(EncryptionAlgorithm.ENCR_AES_CTR.value);

    companion object {
        fun fromValue(value: UInt): XFRMEncryptionAlgorithmType? = entries.find { it.value == value }
    }

    override fun toString(): String {
        return when (this) {
            DES -> "cbc(des)"
            DES3 -> "cbc(des3_ede)"
            CAST -> "cbc(cast5)"
            BLOWFISH -> "cbc(blowfish)"
            NULL -> "ecb(cipher_null)"
            AES_CBC -> "cbc(aes)"
            AES_CTR -> "rfc3686(ctr(aes))"
        }
    }
}

enum class XFRMIntegrityAlgorithmType(val value: UInt) {
    HMAC_MD5_96(AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value),
    HMAC_SHA1_96(AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value),
    AES_XCBC_96(AuthenticationAlgorithm.AUTH_AES_XCBC_96.value);

    companion object {
        fun fromValue(value: UInt): XFRMIntegrityAlgorithmType? = entries.find { it.value == value }
    }


    override fun toString(): String {
        return when (this) {
            HMAC_MD5_96 -> "hmac(md5)"
            HMAC_SHA1_96 -> "hmac(sha1)"
            AES_XCBC_96 -> "xcbc(aes)"
        }
    }
}