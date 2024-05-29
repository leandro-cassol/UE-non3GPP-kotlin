package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AuthenticationRequest {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator.newExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var authenticationRequestMessageIdentity: AuthenticationRequestMessageIdentity = AuthenticationRequestMessageIdentity()
    var spareHalfOctetAndNgksi: SpareHalfOctetAndNgksi = SpareHalfOctetAndNgksi()
    var aBBA: ABBA = ABBA()
    var authenticationParameterRAND: AuthenticationParameterRAND? = null
    var authenticationParameterAUTN: AuthenticationParameterAUTN? = null
    var eAPMessage: EAPMessage? = null

    companion object {
        const val AuthenticationRequestAuthenticationParameterRANDType: UByte = 0x21u
        const val AuthenticationRequestAuthenticationParameterAUTNType: UByte = 0x20u
        const val AuthenticationRequestEAPMessageType: UByte = 0x78u

        fun newAuthenticationRequest(iei: UByte): AuthenticationRequest = AuthenticationRequest()
    }

    fun encodeAuthenticationRequest(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(authenticationRequestMessageIdentity.octet.toByte())
        buffer.put(spareHalfOctetAndNgksi.octet.toByte())
        buffer.put(aBBA.getLen().toByte())
        buffer.put(aBBA.buffer.toByteArray())
        authenticationParameterRAND?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByteArray())
        }
        authenticationParameterAUTN?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        eAPMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray())
        }
    }


    fun decodeAuthenticationRequest(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        authenticationRequestMessageIdentity.octet = buffer.get().toUByte()
        spareHalfOctetAndNgksi.octet = buffer.get().toUByte()

        aBBA.len = buffer.get().toUByte()
        aBBA.setLen(aBBA.getLen())
        aBBA.buffer = UByteArray(aBBA.getLen().toInt())
        buffer.get(aBBA.buffer.toByteArray())

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                AuthenticationRequestAuthenticationParameterRANDType -> {
                    authenticationParameterRAND = AuthenticationParameterRAND.newAuthenticationParameterRAND(ieiN.toUByte())

                    val auxBuffer = ByteArray(authenticationParameterRAND!!.octet.size)
                    buffer.get(auxBuffer)
                    authenticationParameterRAND!!.octet = auxBuffer.toUByteArray()
                }

                AuthenticationRequestAuthenticationParameterAUTNType -> {
                    authenticationParameterAUTN = AuthenticationParameterAUTN.newAuthenticationParameterAUTN(ieiN.toUByte())
                    authenticationParameterAUTN!!.setLen(buffer.get().toUByte())

                    val authBuffer = ByteArray(authenticationParameterAUTN!!.getLen().toInt())
                    buffer.get(authBuffer)
                    authenticationParameterAUTN!!.octet = authBuffer.toUByteArray()
                }

                AuthenticationRequestEAPMessageType -> {
                    eAPMessage = EAPMessage.newEAPMessage(ieiN.toUByte())
                    eAPMessage!!.setLen(buffer.short.toUShort())

                    val eapBuffer = ByteArray(eAPMessage!!.getLen().toInt())
                    buffer.get(eapBuffer)
                    eAPMessage!!.buffer = eapBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}