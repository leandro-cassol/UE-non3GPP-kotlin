package free5gc.nas.nasMessage

import free5gc.nas.nasType.AuthenticationRejectMessageIdentity
import free5gc.nas.nasType.EAPMessage
import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AuthenticationReject {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var authenticationRejectMessageIdentity: AuthenticationRejectMessageIdentity = AuthenticationRejectMessageIdentity()
    var eapMessage: EAPMessage? = null

    companion object {
        const val AuthenticationRejectEAPMessageType: UByte = 0x78u

        fun newAuthenticationReject(iei: UByte): AuthenticationReject {
            return AuthenticationReject()
        }
    }

    fun encodeAuthenticationReject(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(authenticationRejectMessageIdentity.octet.toByte())
        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
    }

    fun decodeAuthenticationReject(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        authenticationRejectMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.hasRemaining()) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                AuthenticationRejectEAPMessageType -> {
                    eapMessage = EAPMessage.newEAPMessage(ieiN.toUByte())
                    eapMessage!!.setLen(buffer.short.toUShort())

                    val eapBuffer = ByteArray(eapMessage!!.getLen().toInt())
                    buffer.get(eapBuffer)
                    eapMessage!!.buffer = eapBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}