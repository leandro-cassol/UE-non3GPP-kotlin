package engine.exchange.pkg.ike.handler


import engine.exchange.pkg.context.ChildSecurityAssociation
import engine.exchange.pkg.context.IkeSecurityAssociation
import engine.exchange.pkg.context.N3iwfContext
import engine.exchange.pkg.ike.message.*
import engine.util.toHexString
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


private val log = LoggerFactory.getLogger("Security")

object RandomNumberGenerator {
    private val randomNumberMaximum = BigInteger(String(CharArray(512) { 'F' }), 16)
    private val randomNumberMinimum = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
    private val random: SecureRandom = SecureRandom()

    fun generateRandomNumber(): BigInteger {
        val random = SecureRandom()
        var number: BigInteger

        while (true) {
            val bytes = ByteArray(256)
            random.nextBytes(bytes)

            number = BigInteger(1, bytes)

            if (number > randomNumberMinimum && number < randomNumberMaximum) {
                break
            }
        }
        if (number.toByteArray().size == 256) {
            val randomInt64 = number.toInt()
            if (randomInt64 > 0) {
                return number
            }
        }
        return generateRandomNumber()
    }

    fun generateRandomUint8(): UByte {
        val number = ByteArray(1)
        random.nextBytes(number)
        return number[0].toUByte()
    }
}

// Diffie-Hellman Exchange
// The strength supplied by group 1 may not be sufficient for typical uses
const val group2PrimeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
        "C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6" +
        "F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE65381FFFFFFFFFFFFFFFF"
const val group2Generator = 2
const val group14PrimeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
        "C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6" +
        "F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804" +
        "F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28F" +
        "B5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
const val group14Generator = 2


fun calculateDiffieHellmanMaterials(secret: BigInteger, peerPublicValue: ByteArray, diffieHellmanGroupNumber: UShort): Pair<ByteArray, ByteArray> {
    val peerPublicValueBig = BigInteger(peerPublicValue)
    val generator: BigInteger
    val factor: BigInteger
    when (diffieHellmanGroupNumber.toUInt()) {
        DiffieHellmanGroup.DH_1024_BIT_MODP.value -> {
            generator = BigInteger.valueOf(group2Generator.toLong())
            factor = BigInteger(group2PrimeString, 16)
        }
        DiffieHellmanGroup.DH_2048_BIT_MODP.value -> {
            generator = BigInteger.valueOf(group14Generator.toLong())
            factor = BigInteger(group14PrimeString, 16)
        }
        else -> {
            throw Exception("Unsupported Diffie-Hellman group: $diffieHellmanGroupNumber")
        }
    }
    var localPublicValue = generator.modPow(secret, factor).toByteArray()
    val prependZero = ByteArray(factor.toByteArray().size - localPublicValue.size)
    localPublicValue = prependZero + localPublicValue
    var sharedKey = peerPublicValueBig.modPow(secret, factor).toByteArray()
    val prependZero2 = ByteArray(factor.toByteArray().size - sharedKey.size)
    sharedKey = prependZero2 + sharedKey
    return Pair(localPublicValue, sharedKey)
}


// Pseudorandom Function
fun newPseudorandomFunction(key: ByteArray, algorithmType: UShort): Mac {
    return when (algorithmType.toUInt()) {
        PRFAlgorithm.PRF_HMAC_MD5.value -> {
            Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(key, "HmacMD5")) }
        }
        PRFAlgorithm.PRF_HMAC_SHA1.value -> {
            Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key, "HmacSHA1")) }
        }
        else -> {
            throw Exception("Unsupported pseudo random function: $algorithmType")
        }
    }
}

// Integrity Algorithm
fun calculateChecksum(key: ByteArray, originData: ByteArray, algorithmType: UShort): ByteArray {
    return when (algorithmType.toUInt()) {
        AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value -> {
            if (key.size != 16) {
                throw Exception("Unmatched input key length")

            }
            val integrityFunction = Mac.getInstance("HmacMD5")
            val secretKey = SecretKeySpec(key, "HmacMD5")
            integrityFunction.init(secretKey)
            return integrityFunction.doFinal(originData)
        }
        AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value -> {
            if (key.size != 20) {
                throw Exception("Unmatched input key length")
            }
            val integrityFunction = Mac.getInstance("HmacSHA1")
            val secretKey = SecretKeySpec(key, "HmacSHA1")
            integrityFunction.init(secretKey)
            val result = integrityFunction.doFinal(originData)
            return Arrays.copyOfRange(result, 0, 12)
        }
        else -> {
            log.error("Unsupported integrity function: $algorithmType")
            throw Exception("Unsupported algorithm")
        }
    }
}

fun verifyIKEChecksum(key: ByteArray, originData: ByteArray, checksum: ByteArray, algorithmType: UShort): Boolean {
    return when (algorithmType.toUInt()) {
        AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value -> {
            if (key.size != 16) {
                throw Exception ("Unmatched input key length")
            } else {
                val integrityFunction = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(key, "HmacMD5")) }
                integrityFunction.update(originData)
                val checksumOfMessage = integrityFunction.doFinal()
                log.trace("Calculated checksum:\n${checksumOfMessage.toHexString()}\nReceived checksum:\n${checksum.toHexString()}")
                checksumOfMessage.contentEquals(checksum)
            }
        }
        AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value -> {
            if (key.size != 20) {
                throw Exception("Unmatched input key length")
            } else {
                val integrityFunction = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key, "HmacSHA1")) }
                integrityFunction.update(originData)
                val checksumOfMessage = integrityFunction.doFinal().copyOf(12)
                checksumOfMessage.contentEquals(checksum)
            }
        }
        else -> {
            log.error("Unsupported integrity function: $algorithmType")
            throw Exception("Unsupported algorithm")
        }
    }
}

// Encryption Algorithm
fun encryptMessage(key: ByteArray, originData: ByteArray, algorithmType: UShort): ByteArray {
    log.info("encryptMessage")

    return when (algorithmType.toUInt()) {
        EncryptionAlgorithm.ENCR_AES_CBC.value -> {

            // Criando um Cipher para criptografia usando AES/CBC/PKCS5Padding
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

            // Padding message
            val originPaddingData = pkcs7Padding(originData, cipher.blockSize)

            // Subtract 1 from the last element of the padded data
            originPaddingData[originPaddingData.size - 1]--

            // Vetor de Inicialização (IV) de 16 bytes
            val initializationVector = ByteArray(cipher.blockSize)
            SecureRandom().nextBytes(initializationVector)

            // Criando uma chave secreta AES 32 bytes (256 bits)
            val block = SecretKeySpec(key, "AES")

            // Inicializando o Cipher para criptografia com a chave e IV
            cipher.init(Cipher.ENCRYPT_MODE, block, IvParameterSpec(initializationVector))

            // Criptografando os dados
            val cipherText = ByteArray(originPaddingData.size + cipher.blockSize)
            cipher.doFinal(originPaddingData, 0, originPaddingData.size, cipherText, 0)

            val result = initializationVector + cipherText.copyOfRange(0, originPaddingData.size)
            log.trace("encryptMessage = [${result.size}] " + result.toUByteArray().contentToString())

            return result
        }
        else -> {
            log.error("Unsupported encryption algorithm: $algorithmType")
            throw Exception("Unsupported algorithm")
        }
    }
}


fun decryptMessage(key: ByteArray, cipherText: ByteArray, algorithmType: UShort): ByteArray {
    return when (algorithmType.toUInt()) {
        EncryptionAlgorithm.ENCR_AES_CBC.value -> {
            if (cipherText.size < 16) {
                throw Exception("Length of cipher text is too short to decrypt")
            }

            val initializationVector = cipherText.copyOfRange(0, 16)
            val encryptedMessage = cipherText.copyOfRange(16, cipherText.size)

            if (encryptedMessage.size % 16 != 0) {
                throw Exception("Cipher text is not a multiple of block size")
            }

            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            val secretKey = SecretKeySpec(key, "AES")
            val ivParameterSpec = IvParameterSpec(initializationVector)

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
            val decryptedMessage = cipher.doFinal(encryptedMessage)
            val padding = decryptedMessage[decryptedMessage.size - 1].toInt() + 1
            Arrays.copyOfRange(decryptedMessage, 0, decryptedMessage.size - padding)
        }
        else -> {
            log.error("Unsupported encryption algorithm: $algorithmType")
            throw Exception("Unsupported algorithm")
        }
    }
}

private fun pkcs7Padding(data: ByteArray, blockSize: Int): ByteArray {
    val padding = blockSize - (data.size % blockSize)
    val paddedData = ByteArray(data.size + padding)
    System.arraycopy(data, 0, paddedData, 0, data.size)
    for (i in data.size until paddedData.size) {
        paddedData[i] = padding.toByte()
    }
    return paddedData
}

// Certificate
fun compareRootCertificate(certificateEncoding: UByte, requestedCertificateAuthorityHash: ByteArray): Boolean {
    if (certificateEncoding.toUInt() != CertificateType.X509CertificateSignature.value) {
        log.debug("Not support certificate type: $certificateEncoding. Reject.")
        return false
    }
    val n3iwfSelf = N3iwfContext.self()
    if (n3iwfSelf.certificateAuthority.isEmpty()) {
        log.error("Certificate authority in context is empty")
        return false
    }
    return n3iwfSelf.certificateAuthority.contentEquals(requestedCertificateAuthorityHash)
}


// Key Gen for IKE SA
fun generateKeyForIKESA(ikeSecurityAssociation: IkeSecurityAssociation?) {
    if (ikeSecurityAssociation == null) {
        throw Exception("IKE SA is nil")
    }
    if (ikeSecurityAssociation.encryptionAlgorithm == null) {
        throw Exception("No encryption algorithm specified")
    }
    if (ikeSecurityAssociation.integrityAlgorithm == null) {
        throw Exception("No integrity algorithm specified")
    }
    if (ikeSecurityAssociation.pseudorandomFunction == null) {
        throw Exception("No pseudorandom function specified")
    }
    if (ikeSecurityAssociation.diffieHellmanGroup == null) {
        throw Exception("No Diffie-hellman group algorithm specified")
    }
    if (ikeSecurityAssociation.concatenatedNonce.isEmpty()) {
        throw Exception("No concatenated nonce data")
    }
    if (ikeSecurityAssociation.diffieHellmanSharedKey.isEmpty()) {
        throw Exception("No Diffie-Hellman shared key")
    }

    val transformIntegrityAlgorithm = ikeSecurityAssociation.integrityAlgorithm
    if (transformIntegrityAlgorithm == null) {
        throw Exception("Transform Integrity Algorithm is nil")
    }

    val transformEncryptionAlgorithm = ikeSecurityAssociation.encryptionAlgorithm
    if (transformEncryptionAlgorithm == null) {
        throw Exception("Transform Encryption Algorithm is nil")
    }

    val transformPseudorandomFunction = ikeSecurityAssociation.pseudorandomFunction
    if (transformPseudorandomFunction == null) {
        throw Exception("Transform Pseudorandom Function is nil")
    }

    val (lengthSkD, okSkD) = getKeyLength(transformPseudorandomFunction.transformType,
        transformPseudorandomFunction.transformID, transformPseudorandomFunction.attributePresent,
        transformPseudorandomFunction.attributeValue)
    if (!okSkD) {
        throw Exception("Get key length failed")
    }

    val (lengthSkAi, okSkAi) = getKeyLength(transformIntegrityAlgorithm.transformType,
        transformIntegrityAlgorithm.transformID, transformIntegrityAlgorithm.attributePresent,
        transformIntegrityAlgorithm.attributeValue)
    if (!okSkAi) {
        throw Exception("Get key length failed")
    }
    val lengthSkAr = lengthSkAi
    val (lengthSkEi, okSkEi) = getKeyLength(transformEncryptionAlgorithm.transformType,
        transformEncryptionAlgorithm.transformID, transformEncryptionAlgorithm.attributePresent,
        transformEncryptionAlgorithm.attributeValue)
    if (!okSkEi) {
        throw Exception("Get key length failed")
    }
    val lengthSkEr = lengthSkEi
    val lengthSkPi = lengthSkD
    val lengthSkPr = lengthSkD
    val totalKeyLength = lengthSkD + lengthSkAi + lengthSkAr + lengthSkEi + lengthSkEr + lengthSkPi + lengthSkPr

    val pseudorandomFunction = newPseudorandomFunction(ikeSecurityAssociation.concatenatedNonce, transformPseudorandomFunction.transformID)
    val sKeySeed = pseudorandomFunction.doFinal()
    val seed = concatenateNonceAndSPI(
        ikeSecurityAssociation.concatenatedNonce,
        ikeSecurityAssociation.remoteSPI,
        ikeSecurityAssociation.localSPI
    )

    var keyStream = ByteArray(0)
    var generatedKeyBlock = ByteArray(0)
    var index: Byte = 1
    while (keyStream.size < totalKeyLength) {
        val pseudorandomFunction2 = newPseudorandomFunction(sKeySeed, transformPseudorandomFunction.transformID)
        pseudorandomFunction2.update(generatedKeyBlock + seed + index)
        generatedKeyBlock = pseudorandomFunction2.doFinal()
        keyStream += generatedKeyBlock
        index++
    }
    ikeSecurityAssociation.skD = keyStream.copyOf(lengthSkD)
    keyStream = keyStream.copyOfRange(lengthSkD, keyStream.size)
    ikeSecurityAssociation.skAi = keyStream.copyOf(lengthSkAi)
    keyStream = keyStream.copyOfRange(lengthSkAi, keyStream.size)
    ikeSecurityAssociation.skAr = keyStream.copyOf(lengthSkAr)
    keyStream = keyStream.copyOfRange(lengthSkAr, keyStream.size)
    ikeSecurityAssociation.skEi = keyStream.copyOf(lengthSkEi)
    keyStream = keyStream.copyOfRange(lengthSkEi, keyStream.size)
    ikeSecurityAssociation.skEr = keyStream.copyOf(lengthSkEr)
    keyStream = keyStream.copyOfRange(lengthSkEr, keyStream.size)
    ikeSecurityAssociation.skPi = keyStream.copyOf(lengthSkPi)
    keyStream = keyStream.copyOfRange(lengthSkPi, keyStream.size)
    ikeSecurityAssociation.skPr = keyStream.copyOf(lengthSkPr)
    log.debug("====== IKE Security Association Info =====")
    log.debug("Initiator's SPI: ${ikeSecurityAssociation.remoteSPI.toString(16)}")
    log.debug("Responder's  SPI: ${ikeSecurityAssociation.localSPI.toString(16)}")
    log.debug("Encryption Algorithm: ${ikeSecurityAssociation.encryptionAlgorithm!!.transformID}")
    log.debug("SK_ei: ${ikeSecurityAssociation.skEi.toHexString()}")
    log.debug("SK_er: ${ikeSecurityAssociation.skEr.toHexString()}")
    log.debug("Integrity Algorithm: ${ikeSecurityAssociation.integrityAlgorithm!!.transformID}")
    log.debug("SK_ai: ${ikeSecurityAssociation.skAi.toHexString()}")
    log.debug("SK_ar: ${ikeSecurityAssociation.skAr.toHexString()}")
    log.debug("SK_pi: ${ikeSecurityAssociation.skPi.toHexString()}")
    log.debug("SK_pr: ${ikeSecurityAssociation.skPr.toHexString()}")
}




fun getKeyLength(transformType: UByte, transformID: UShort, attributePresent: Boolean, attributeValue: UShort): Pair<Int, Boolean> {
    return when (transformType.toInt()) {
        PayloadType.TypeEncryptionAlgorithm.value.toInt() -> when (transformID.toInt()) {
            EncryptionAlgorithm.ENCR_DES_IV64.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_DES.value.toInt() -> 8 to true
            EncryptionAlgorithm.ENCR_3DES.value.toInt() -> 24 to true
            EncryptionAlgorithm.ENCR_RC5.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_IDEA.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_CAST.value.toInt() -> if (attributePresent) {
                when (attributeValue.toInt()) {
                    128 -> 16 to true
                    256 -> 0 to false
                    else -> 0 to false
                }
            } else 0 to false
            EncryptionAlgorithm.ENCR_BLOWFISH.value.toInt() -> if (attributePresent) {
                if (attributeValue.toInt() < 40 || attributeValue.toInt() > 448) 0 to false
                else (attributeValue.toInt() / 8) to true
            } else 0 to false
            EncryptionAlgorithm.ENCR_3IDEA.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_DES_IV32.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_NULL.value.toInt() -> 0 to true
            EncryptionAlgorithm.ENCR_AES_CBC.value.toInt() -> if (attributePresent) {
                when (attributeValue.toInt()) {
                    128 -> 16 to true
                    192 -> 24 to true
                    256 -> 32 to true
                    else -> 0 to false
                }
            } else 0 to false
            EncryptionAlgorithm.ENCR_AES_CTR.value.toInt() -> if (attributePresent) {
                when (attributeValue.toInt()) {
                    128 -> 20 to true
                    192 -> 28 to true
                    256 -> 36 to true
                    else -> 0 to false
                }
            } else 0 to false
            else -> 0 to false
        }
        PayloadType.TypePseudorandomFunction.value.toInt() -> when (transformID.toInt()) {
            PRFAlgorithm.PRF_HMAC_MD5.value.toInt() -> 16 to true
            PRFAlgorithm.PRF_HMAC_SHA1.value.toInt() -> 20 to true
            PRFAlgorithm.PRF_HMAC_TIGER.value.toInt() -> 0 to false
            else -> 0 to false
        }
        PayloadType.TypeIntegrityAlgorithm.value.toInt() -> when (transformID.toInt()) {
            AuthenticationAlgorithm.AUTH_NONE.value.toInt() -> 0 to false
            AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value.toInt()-> 16 to true
            AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value.toInt() -> 20 to true
            AuthenticationAlgorithm.AUTH_DES_MAC.value.toInt() -> 0 to false
            AuthenticationAlgorithm.AUTH_KPDK_MD5.value.toInt() -> 0 to false
            AuthenticationAlgorithm.AUTH_AES_XCBC_96.value.toInt() -> 0 to false
            else -> 0 to false
        }
        PayloadType.TypeDiffieHellmanGroup.value.toInt() -> when (transformID.toInt()) {
            DiffieHellmanGroup.DH_NONE.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_768_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_1024_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_1536_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_2048_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_3072_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_4096_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_6144_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_8192_BIT_MODP.value.toInt() -> 0 to false
            else -> 0 to false
        }
        else -> 0 to false
    }
}


// Key Gen for child SA
fun generateKeyForChildSA(ikeSecurityAssociation: IkeSecurityAssociation?,
                          childSecurityAssociation: ChildSecurityAssociation?) {
    if (ikeSecurityAssociation == null) {
        throw Exception("IKE SA is nil")
    }
    if (childSecurityAssociation == null) {
        throw Exception("Child SA is nil")
    }

    // Check if the context contain needed data
    if (ikeSecurityAssociation.pseudorandomFunction == null) {
        throw Exception("No pseudorandom function specified")
    }
    if (ikeSecurityAssociation.ikeAuthResponseSA == null) {
        throw Exception("No IKE_AUTH response SA specified")
    }
    if (ikeSecurityAssociation.ikeAuthResponseSA!!.proposals.isEmpty()) {
        throw Exception("No proposal in IKE_AUTH response SA")
    }
    if (ikeSecurityAssociation.ikeAuthResponseSA!!.proposals[0].encryptionAlgorithm.transforms.isEmpty()) {
        throw Exception("No encryption algorithm specified")
    }
    if (ikeSecurityAssociation.skD.isEmpty()) {
        throw Exception("No key deriving key")
    }

    // Transforms
    val transformPseudorandomFunction = ikeSecurityAssociation.pseudorandomFunction
    if (transformPseudorandomFunction == null) {
        throw Exception("Transform Pseudorandom Function is nil")
    }

    val transformEncryptionAlgorithmForIPSec = ikeSecurityAssociation.ikeAuthResponseSA!!.proposals[0].encryptionAlgorithm.transforms[0]
    var transformIntegrityAlgorithmForIPSec: Transform? = null
    if (ikeSecurityAssociation.ikeAuthResponseSA!!.proposals[0].integrityAlgorithm.transforms.isNotEmpty()) {
        transformIntegrityAlgorithmForIPSec = ikeSecurityAssociation.ikeAuthResponseSA!!.proposals[0].integrityAlgorithm.transforms[0]
    }

    // Get key length for encryption and integrity key for IPSec
    val lengthEncryptionKeyIPSec: Int
    var lengthIntegrityKeyIPSec = 0
    val keyLengthResult = getKeyLength(transformEncryptionAlgorithmForIPSec.transformType,
        transformEncryptionAlgorithmForIPSec.transformID,
        transformEncryptionAlgorithmForIPSec.attributePresent,
        transformEncryptionAlgorithmForIPSec.attributeValue)
    if (keyLengthResult != null) {
        lengthEncryptionKeyIPSec = keyLengthResult.first
    } else {
        // Log error: Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.
        throw Exception("Get key length failed")
    }
    if (transformIntegrityAlgorithmForIPSec != null) {
        val integrityKeyLengthResult = getKeyLength(transformIntegrityAlgorithmForIPSec.transformType,
            transformIntegrityAlgorithmForIPSec.transformID,
            transformIntegrityAlgorithmForIPSec.attributePresent,
            transformIntegrityAlgorithmForIPSec.attributeValue)
        if (integrityKeyLengthResult != null) {
            lengthIntegrityKeyIPSec = integrityKeyLengthResult.first
        } else {
            // Log error: Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.
            throw Exception("Get key length failed")
        }
    }
    val totalKeyLength: Int = (lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec) * 2

    // Generate key for child security association as specified in RFC 7296 section 2.17
    val seed = ikeSecurityAssociation.concatenatedNonce
    var pseudorandomFunction: Mac
    var keyStream = ByteArray(0)
    var generatedKeyBlock = ByteArray(0)
    var index = 1.toByte()
    while (keyStream.size < totalKeyLength) {
        pseudorandomFunction = newPseudorandomFunction(ikeSecurityAssociation.skD, transformPseudorandomFunction.transformID)
        pseudorandomFunction.update(generatedKeyBlock + seed + byteArrayOf(index))
        generatedKeyBlock = pseudorandomFunction.doFinal()
        keyStream += generatedKeyBlock
        index++
    }
    childSecurityAssociation.initiatorToResponderEncryptionKey = keyStream.copyOfRange(0, lengthEncryptionKeyIPSec)
    keyStream = keyStream.copyOfRange(lengthEncryptionKeyIPSec, keyStream.size)

    childSecurityAssociation.initiatorToResponderIntegrityKey = keyStream.copyOfRange(0, lengthIntegrityKeyIPSec)
    keyStream = keyStream.copyOfRange(lengthIntegrityKeyIPSec, keyStream.size)

    childSecurityAssociation.responderToInitiatorEncryptionKey = keyStream.copyOfRange(0, lengthEncryptionKeyIPSec)
    keyStream = keyStream.copyOfRange(lengthEncryptionKeyIPSec, keyStream.size)

    childSecurityAssociation.responderToInitiatorIntegrityKey = keyStream.copyOfRange(0, lengthIntegrityKeyIPSec)
}


// Decrypt
fun decryptProcedure(ikeSecurityAssociation: IkeSecurityAssociation?,
                     ikeMessage: IKEMessage?,
                     encryptedPayload: Encrypted?): IKEPayloadContainer {
    // Check parameters
    if (ikeSecurityAssociation == null) {
        throw Exception("IKE SA is nil")
    }
    if (ikeMessage == null) {
        throw Exception("IKE message is nil")
    }
    if (encryptedPayload == null) {
        throw Exception("IKE encrypted payload is nil")
    }

    // Check if the context contain needed data
    if (ikeSecurityAssociation.integrityAlgorithm == null) {
        throw Exception("No integrity algorithm specified")
    }
    if (ikeSecurityAssociation.encryptionAlgorithm == null) {
        throw Exception("No encryption algorithm specified")
    }
    if (ikeSecurityAssociation.skAi.isEmpty()) {
        throw Exception("No initiator's integrity key")
    }
    if (ikeSecurityAssociation.skEi.isEmpty()) {
        throw Exception("No initiator's encryption key")
    }

    // Load needed information
    val transformIntegrityAlgorithm = ikeSecurityAssociation.integrityAlgorithm
    if (transformIntegrityAlgorithm == null) {
        throw Exception("Transform Integrity Algorithm is nil")
    }

    val transformEncryptionAlgorithm = ikeSecurityAssociation.encryptionAlgorithm
    if (transformEncryptionAlgorithm == null) {
        throw Exception("Transform Encryption Algorithm is nil")
    }

    val checksumLengthResult = getOutputLength(
        transformIntegrityAlgorithm.transformType,
        transformIntegrityAlgorithm.transformID,
        transformIntegrityAlgorithm.attributePresent,
        transformIntegrityAlgorithm.attributeValue
    )

    val checksumLength = checksumLengthResult.first
    val ok = checksumLengthResult.second
    if (!ok) {
        log.error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
        throw Exception("Get key length failed")
    }

    // Checksum
    val checksum = encryptedPayload.encryptedData.copyOfRange(encryptedPayload.encryptedData.size - checksumLength, encryptedPayload.encryptedData.size)
    val ikeMessageData = ikeMessage.encode()
    val ikeMessageDataWithoutChecksum = ikeMessageData.copyOfRange(0, ikeMessageData.size - checksumLength)
    val okChecksum = verifyIKEChecksum(
        ikeSecurityAssociation.skAi,
        ikeMessageDataWithoutChecksum,
        checksum,
        transformIntegrityAlgorithm.transformID
    )

    if (!okChecksum) {
        log.warn("Message checksum failed. Drop the message.")
        throw Exception("Checksum failed, drop.")
    }

    // Decrypt
    val encryptedData = encryptedPayload.encryptedData.copyOfRange(0, encryptedPayload.encryptedData.size - checksumLength)
    val plainText = decryptMessage(ikeSecurityAssociation.skEi, encryptedData, transformEncryptionAlgorithm.transformID)
    val decryptedIKEPayload = IKEPayloadContainer()
    try {
        decryptedIKEPayload.decode(encryptedPayload.nextPayload, plainText)
    } catch (e: Exception) {
        throw Exception("Decoding decrypted payload failed")
    }
    return decryptedIKEPayload
}


// Encrypt
fun encryptProcedure(ikeSecurityAssociation: IkeSecurityAssociation?,
                     ikePayload: IKEPayloadContainer?,
                     responseIKEMessage: IKEMessage?) {
    // Check parameters
    if (ikeSecurityAssociation == null) {
        throw Exception("IKE SA is nil")
    }
    if (ikePayload == null || ikePayload.isEmpty()) {
        throw Exception("No IKE payload to be encrypted")
    }
    if (responseIKEMessage == null) {
        throw Exception("Response IKE message is nil")
    }

    // Check if the context contain needed data
    if (ikeSecurityAssociation.integrityAlgorithm == null) {
        throw Exception("No integrity algorithm specified")
    }
    if (ikeSecurityAssociation.encryptionAlgorithm == null) {
        throw Exception("No encryption algorithm specified")
    }
    if (ikeSecurityAssociation.skAr.isEmpty()) {
        throw Exception("No responder's integrity key")
    }
    if (ikeSecurityAssociation.skEr.isEmpty()) {
        throw Exception("No responder's encryption key")
    }

    // Load needed information
    val transformIntegrityAlgorithm = ikeSecurityAssociation.integrityAlgorithm
    if (transformIntegrityAlgorithm == null) {
        throw Exception("Transform Integrity Algorithm is nil")
    }

    val transformEncryptionAlgorithm = ikeSecurityAssociation.encryptionAlgorithm
    if (transformEncryptionAlgorithm == null) {
        throw Exception("Transform Encryption Algorithm is nil")
    }

    val (checksumLength, ok) = getOutputLength(
        transformIntegrityAlgorithm.transformType,
        transformIntegrityAlgorithm.transformID,
        transformIntegrityAlgorithm.attributePresent,
        transformIntegrityAlgorithm.attributeValue
    )

    if (!ok) {
        log.error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
        throw Exception("Get key length failed")
    }

    // Encrypting
    val ikePayloadData = ikePayload.encode()

    val encryptedData = encryptMessage(ikeSecurityAssociation.skEr, ikePayloadData, transformEncryptionAlgorithm.transformID)

    val paddedEncryptedData = encryptedData + ByteArray(checksumLength)
    val sk = responseIKEMessage.payloads.buildEncrypted(ikePayload[0].type(), paddedEncryptedData)

    // Calculate checksum
    val responseIKEMessageData = responseIKEMessage.encode()

    val checksumOfMessage = calculateChecksum(ikeSecurityAssociation.skAr,
        responseIKEMessageData.sliceArray(0 until responseIKEMessageData.size - checksumLength),
        transformIntegrityAlgorithm.transformID)

    val checksumField = sk.encryptedData.sliceArray(sk.encryptedData.size - checksumLength until sk.encryptedData.size)
    checksumField.copyInto(checksumOfMessage)
}

fun getKeyLength(transformType: Byte, transformID: Short, attributePresent: Boolean,
                 attributeValue: Short): Pair<Int, Boolean> {
    when (transformType.toUInt()) {
        PayloadType.TypeEncryptionAlgorithm.value -> {
            when (transformID.toUInt()) {
                EncryptionAlgorithm.ENCR_DES_IV64.value -> return Pair(0, false)
                EncryptionAlgorithm.ENCR_DES.value -> return Pair(8, true)
                EncryptionAlgorithm.ENCR_3DES.value -> return Pair(24, true)
                EncryptionAlgorithm.ENCR_RC5.value -> return Pair(0, false)
                EncryptionAlgorithm.ENCR_IDEA.value -> return Pair(0, false)
                EncryptionAlgorithm.ENCR_CAST.value -> {
                    if (attributePresent) {
                        when (attributeValue) {
                            128.toShort() -> return Pair(16, true)
                            256.toShort() -> return Pair(0, false)
                            else -> return Pair(0, false)
                        }
                    }
                    return Pair(0, false)
                }
                EncryptionAlgorithm.ENCR_BLOWFISH.value -> {
                    if (attributePresent) {
                        if (attributeValue < 40) {
                            return Pair(0, false)
                        } else if (attributeValue > 448) {
                            return Pair(0, false)
                        } else {
                            return Pair(attributeValue.toInt() / 8, true)
                        }
                    } else {
                        return Pair(0, false)
                    }
                }
                EncryptionAlgorithm.ENCR_3IDEA.value -> return Pair(0, false)
                EncryptionAlgorithm.ENCR_DES_IV32.value -> return Pair(0, false)
                EncryptionAlgorithm.ENCR_NULL.value -> return Pair(0, true)
                EncryptionAlgorithm.ENCR_AES_CBC.value -> {
                    if (attributePresent) {
                        when (attributeValue) {
                            128.toShort() -> return Pair(16, true)
                            192.toShort() -> return Pair(24, true)
                            256.toShort() -> return Pair(32, true)
                            else -> return Pair(0, false)
                        }
                    } else {
                        return Pair(0, false)
                    }
                }
                EncryptionAlgorithm.ENCR_AES_CTR.value -> {
                    if (attributePresent) {
                        when (attributeValue) {
                            128.toShort() -> return Pair(20, true)
                            192.toShort() -> return Pair(28, true)
                            256.toShort() -> return Pair(36, true)
                            else -> return Pair(0, false)
                        }
                    } else {
                        return Pair(0, false)
                    }
                }
                else -> return Pair(0, false)
            }
        }
        PayloadType.TypePseudorandomFunction.value -> {
            when (transformID.toUInt()) {
                PRFAlgorithm.PRF_HMAC_MD5.value -> return Pair(16, true)
                PRFAlgorithm.PRF_HMAC_SHA1.value -> return Pair(20, true)
                PRFAlgorithm.PRF_HMAC_TIGER.value -> return Pair(0, false)
                else -> return Pair(0, false)
            }
        }
        PayloadType.TypeIntegrityAlgorithm.value -> {
            when (transformID.toUInt()) {
                AuthenticationAlgorithm.AUTH_NONE.value -> return Pair(0, false)
                AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value -> return Pair(16, true)
                AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value -> return Pair(20, true)
                AuthenticationAlgorithm.AUTH_DES_MAC.value -> return Pair(0, false)
                AuthenticationAlgorithm.AUTH_KPDK_MD5.value -> return Pair(0, false)
                AuthenticationAlgorithm.AUTH_AES_XCBC_96.value -> return Pair(0, false)
                else -> return Pair(0, false)
            }
        }
        PayloadType.TypeDiffieHellmanGroup.value -> {
            when (transformID.toUInt()) {
                DiffieHellmanGroup.DH_NONE.value -> return Pair(0, false)
                DiffieHellmanGroup.DH_768_BIT_MODP.value -> return Pair(0, false)
                DiffieHellmanGroup.DH_1024_BIT_MODP.value -> return Pair(0, false)
                DiffieHellmanGroup.DH_1536_BIT_MODP.value -> return Pair(0, false)
                DiffieHellmanGroup.DH_2048_BIT_MODP.value -> return Pair(0, false)
                DiffieHellmanGroup.DH_3072_BIT_MODP.value -> return Pair(0, false)
                DiffieHellmanGroup.DH_4096_BIT_MODP.value -> return Pair(0, false)
                DiffieHellmanGroup.DH_6144_BIT_MODP.value -> return Pair(0, false)
                DiffieHellmanGroup.DH_8192_BIT_MODP.value -> return Pair(0, false)
                else -> return Pair(0, false)
            }
        }
        else -> return Pair(0, false)
    }
}

fun getOutputLength(transformType: UByte, transformID: UShort, attributePresent: Boolean,
                    attributeValue: UShort): Pair<Int, Boolean> {
    when (transformType.toUInt()) {
        PayloadType.TypePseudorandomFunction.value -> {
            when (transformID.toUInt()) {
                PRFAlgorithm.PRF_HMAC_MD5.value -> return Pair(16, true)
                PRFAlgorithm.PRF_HMAC_SHA1.value -> return Pair(20, true)
                PRFAlgorithm.PRF_HMAC_TIGER.value -> return Pair(0, false)
                else -> return Pair(0, false)
            }
        }
        PayloadType.TypeIntegrityAlgorithm.value -> {
            when (transformID.toUInt()) {
                AuthenticationAlgorithm.AUTH_NONE.value -> return Pair(0, false)
                AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value -> return Pair(12, true)
                AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value -> return Pair(12, true)
                AuthenticationAlgorithm.AUTH_DES_MAC.value -> return Pair(0, false)
                AuthenticationAlgorithm.AUTH_KPDK_MD5.value -> return Pair(0, false)
                AuthenticationAlgorithm.AUTH_AES_XCBC_96.value -> return Pair(0, false)
                else -> return Pair(0, false)
            }
        }
        else -> return Pair(0, false)
    }
}


fun concatenateNonceAndSPI(nonce: ByteArray, spiInitiator: ULong, spiResponder: ULong): ByteArray {
    val spi = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(spiInitiator.toLong()).array()
    val newSlice = nonce + spi
    ByteBuffer.wrap(spi).order(ByteOrder.BIG_ENDIAN).putLong(spiResponder.toLong())
    return newSlice + spi
}