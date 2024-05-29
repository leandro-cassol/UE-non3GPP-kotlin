package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AuthenticationResponse {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var authenticationResponseMessageIdentity: AuthenticationResponseMessageIdentity = AuthenticationResponseMessageIdentity()
    var authenticationResponseParameter: AuthenticationResponseParameter? = null
    var eapMessage: EAPMessage? = null

    companion object {
        const val AuthenticationResponseAuthenticationResponseParameterType: UByte = 0x2Du
        const val AuthenticationResponseEAPMessageType: UByte = 0x78u

        fun NewAuthenticationResponse(iei: UByte): AuthenticationResponse {
            return AuthenticationResponse()
        }
    }

    fun encodeAuthenticationResponse(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(authenticationResponseMessageIdentity.octet.toByte())

        authenticationResponseParameter?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
    }

    fun decodeAuthenticationResponse(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        authenticationResponseMessageIdentity.octet = buffer.get().toUByte()
        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                AuthenticationResponseAuthenticationResponseParameterType -> {
                    authenticationResponseParameter = AuthenticationResponseParameter.newAuthenticationResponseParameter(ieiN.toUByte())
                    authenticationResponseParameter!!.setLen(buffer.get().toUByte())

                    val auxByteArray = ByteArray(authenticationResponseParameter!!.getLen().toInt())
                    buffer.get(auxByteArray)
                    authenticationResponseParameter!!.octet = auxByteArray.toUByteArray()

                }

                AuthenticationResponseEAPMessageType -> {
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