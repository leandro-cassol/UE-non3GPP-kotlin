package engine.util

import engine.exchange.pkg.context.IkeSecurityAssociation
import engine.exchange.pkg.ike.handler.*
import engine.exchange.pkg.ike.message.Encrypted
import engine.exchange.pkg.ike.message.IKEMessage
import engine.exchange.pkg.ike.message.IKEPayloadContainer
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import javax.crypto.Mac

private val log = LoggerFactory.getLogger("CryptoUtils")

fun encryptProcedure(ikeSecurityAssociation: IkeSecurityAssociation, ikePayload: IKEPayloadContainer, responseIKEMessage: IKEMessage) {
    log.trace("EncryptProcedure")
    val transformIntegrityAlgorithm = ikeSecurityAssociation.integrityAlgorithm
    val transformEncryptionAlgorithm = ikeSecurityAssociation.encryptionAlgorithm
    val checksumLength = 12

    val notificationPayloadData = try {
        ikePayload.encode()
    } catch (e: Exception) {
        throw Exception("Encoding IKE payload failed.")
    }

    val encryptedData = try {
        encryptMessage(ikeSecurityAssociation.skEi, notificationPayloadData, transformEncryptionAlgorithm!!.transformID)
    } catch (e: Exception) {
        throw Exception("Error encrypting message")
    }

    val paddedEncryptedData = encryptedData + ByteArray(checksumLength)
    val sk = responseIKEMessage.payloads.buildEncrypted(ikePayload[0].type(), paddedEncryptedData)

    val responseIKEMessageData = try {
        responseIKEMessage.encode()
    } catch (e: Exception) {
        throw Exception("Encoding IKE message error")
    }

    val checksumOfMessage = try {
        calculateChecksum(ikeSecurityAssociation.skAi, responseIKEMessageData.copyOfRange(0, responseIKEMessageData.size - checksumLength), transformIntegrityAlgorithm!!.transformID)
    } catch (e: Exception) {
        throw Exception("Error calculating checksum")
    }
    // Adiciona checksumOfMessage ao final da encryptedData
    sk.encryptedData = sk.encryptedData.copyOfRange(0, sk.encryptedData.size - checksumLength) + checksumOfMessage
}

fun decryptProcedure(ikeSecurityAssociation: IkeSecurityAssociation, ikeMessage: IKEMessage, encryptedPayload: Encrypted): IKEPayloadContainer {
    log.trace("DecryptProcedure")
    val transformIntegrityAlgorithm = ikeSecurityAssociation.integrityAlgorithm
    val transformEncryptionAlgorithm = ikeSecurityAssociation.encryptionAlgorithm
    val checksumLength = 12

    val checksum = encryptedPayload.encryptedData.sliceArray(encryptedPayload.encryptedData.size - checksumLength until encryptedPayload.encryptedData.size)
    val ikeMessageData = ikeMessage.encode()
    val ok = verifyIKEChecksum(ikeSecurityAssociation.skAr, ikeMessageData.sliceArray(0 until ikeMessageData.size - checksumLength), checksum, transformIntegrityAlgorithm!!.transformID)
    if (!ok) {
        throw Exception("Checksum failed, drop.")
    }

    val encryptedData = encryptedPayload.encryptedData.sliceArray(0 until encryptedPayload.encryptedData.size - checksumLength)
    val plainText = decryptMessage(ikeSecurityAssociation.skEr, encryptedData, transformEncryptionAlgorithm!!.transformID)
    val decryptedIKEPayload = IKEPayloadContainer()
    try {
        decryptedIKEPayload.decode(encryptedPayload.nextPayload, plainText)
    } catch (e: Exception) {
        throw Exception("Decoding decrypted payload failed")
    }
    return decryptedIKEPayload
}

fun generateKeyForIKESA(ikeSecurityAssociation: IkeSecurityAssociation) {
    val transformPseudorandomFunction = ikeSecurityAssociation.pseudorandomFunction

    val lengthSKd = 20
    val lengthSKai = 20
    val lengthSKar = lengthSKai
    val lengthSKei = 32
    val lengthSKer = lengthSKei
    val lengthSKpi = lengthSKd
    val lengthSKpr = lengthSKd
    val totalKeyLength = lengthSKd + lengthSKai + lengthSKar + lengthSKei + lengthSKer + lengthSKpi + lengthSKpr

    var pseudorandomFunction: Mac
    try {
        pseudorandomFunction = newPseudorandomFunction(ikeSecurityAssociation.concatenatedNonce, transformPseudorandomFunction!!.transformID)
    } catch (e: Exception) {
        throw Exception("New pseudorandom function failed")
    }

    pseudorandomFunction.update(ikeSecurityAssociation.diffieHellmanSharedKey)
    val sKeySeed = pseudorandomFunction.doFinal()
    val seed = concatenateNonceAndSPI(
        ikeSecurityAssociation.concatenatedNonce,
        ikeSecurityAssociation.localSPI,
        ikeSecurityAssociation.remoteSPI
    )

    var keyStream = ByteArray(0)
    var generatedKeyBlock = ByteArray(0)
    var index = 1.toByte()
    while (keyStream.size < totalKeyLength) {
        try {
            pseudorandomFunction = newPseudorandomFunction(sKeySeed, transformPseudorandomFunction.transformID)
            pseudorandomFunction.update(generatedKeyBlock + seed + index)
            generatedKeyBlock = pseudorandomFunction.doFinal()
            keyStream += generatedKeyBlock
        } catch (e: Exception) {
            throw Exception("Pseudorandom function write failed")
        }
        index++
    }

    ikeSecurityAssociation.skD = keyStream.copyOfRange(0, lengthSKd)
    keyStream = keyStream.drop(lengthSKd).toByteArray()
    ikeSecurityAssociation.skAi = keyStream.copyOfRange(0, lengthSKai)
    keyStream = keyStream.drop(lengthSKai).toByteArray()
    ikeSecurityAssociation.skAr = keyStream.copyOfRange(0, lengthSKar)
    keyStream = keyStream.drop(lengthSKar).toByteArray()
    ikeSecurityAssociation.skEi = keyStream.copyOfRange(0, lengthSKei)
    keyStream = keyStream.drop(lengthSKei).toByteArray()
    ikeSecurityAssociation.skEr = keyStream.copyOfRange(0, lengthSKer)
    keyStream = keyStream.drop(lengthSKer).toByteArray()
    ikeSecurityAssociation.skPi = keyStream.copyOfRange(0, lengthSKpi)
    keyStream = keyStream.drop(lengthSKpi).toByteArray()
    ikeSecurityAssociation.skPr = keyStream.copyOfRange(0, lengthSKpr)
    //keyStream = keyStream.drop(lengthSKpr).toByteArray()
}

fun concatenateNonceAndSPI(nonce: ByteArray, spiInitiator: ULong, spiResponder: ULong): ByteArray {
    val spiBuffer = ByteBuffer.allocate(8)

    spiBuffer.putLong(spiInitiator.toLong())
    var newSlice = nonce + spiBuffer.array()

    spiBuffer.clear()
    spiBuffer.putLong(spiResponder.toLong())
    newSlice += spiBuffer.array()

    return newSlice
}
