package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AuthenticationFailure {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var authenticationFailureMessageIdentity: AuthenticationFailureMessageIdentity = AuthenticationFailureMessageIdentity()
    var cause5GMM: Cause5GMM = Cause5GMM()
    var authenticationFailureParameter: AuthenticationFailureParameter? = null

    companion object {
        const val AuthenticationFailureAuthenticationFailureParameterType: UByte = 0x30u

        fun newAuthenticationFailure(iei: UByte): AuthenticationFailure {
            return AuthenticationFailure()
        }
    }

    fun encodeAuthenticationFailure(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(authenticationFailureMessageIdentity.octet.toByte())
        buffer.put(cause5GMM.octet.toByte())

        authenticationFailureParameter?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodeAuthenticationFailure(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        authenticationFailureMessageIdentity.octet = buffer.get().toUByte()
        cause5GMM.octet = buffer.get().toUByte()

        while (buffer.hasRemaining()) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                AuthenticationFailureAuthenticationFailureParameterType -> {
                    authenticationFailureParameter = AuthenticationFailureParameter.newAuthenticationFailureParameter(ieiN.toUByte())
                    authenticationFailureParameter!!.setLen(buffer.get().toUByte())

                    val authBuffer = ByteArray(authenticationFailureParameter!!.getLen().toInt())
                    buffer.get(authBuffer)
                    authenticationFailureParameter!!.octet = authBuffer.toUByteArray()
                }
                else -> {}
            }
        }
    }
}