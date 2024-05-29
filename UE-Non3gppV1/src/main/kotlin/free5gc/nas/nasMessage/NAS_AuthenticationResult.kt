package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AuthenticationResult {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var authenticationResultMessageIdentity: AuthenticationResultMessageIdentity = AuthenticationResultMessageIdentity()
    var spareHalfOctetAndNgksi: SpareHalfOctetAndNgksi = SpareHalfOctetAndNgksi()
    var eapMessage: EAPMessage = EAPMessage()
    var abba: ABBA? = null

    companion object {
        const val AuthenticationResultABBAType: UByte = 0x38u

        fun NewAuthenticationResult(iei: UByte): AuthenticationResult {
            return AuthenticationResult()
        }
    }

    fun encodeAuthenticationResult(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(authenticationResultMessageIdentity.octet.toByte())
        buffer.put(spareHalfOctetAndNgksi.octet.toByte())

        buffer.putShort(eapMessage.getLen().toShort())
        buffer.put(eapMessage.buffer.toByteArray())

        abba?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
    }

    fun decodeAuthenticationResult(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        authenticationResultMessageIdentity.octet = buffer.get().toUByte()
        spareHalfOctetAndNgksi.octet = buffer.get().toUByte()

        eapMessage.len = buffer.getShort().toUShort()
        eapMessage.setLen(eapMessage.getLen())

        val eapBuffer = ByteArray(eapMessage.getLen().toInt())
        buffer.get(eapBuffer)
        eapMessage.buffer = eapBuffer.toUByteArray()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                AuthenticationResultABBAType -> {
                    abba = ABBA.newABBA(ieiN.toUByte())
                    abba!!.setLen(buffer.get().toUByte())

                    val abbaBuffer = ByteArray(abba!!.getLen().toInt())
                    buffer.get(abbaBuffer)
                    abba!!.buffer = abbaBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}