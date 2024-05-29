package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RegistrationReject {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var registrationRejectMessageIdentity: RegistrationRejectMessageIdentity = RegistrationRejectMessageIdentity()
    var cause5GMM: Cause5GMM = Cause5GMM()
    var t3346Value: T3346Value? = null
    var t3502Value: T3502Value? = null
    var eapMessage: EAPMessage? = null

    companion object {
        const val RegistrationRejectT3346ValueType: UByte = 0x5Fu
        const val RegistrationRejectT3502ValueType: UByte = 0x16u
        const val RegistrationRejectEAPMessageType: UByte = 0x78u

        fun NewRegistrationReject(iei: UByte): RegistrationReject {
            return RegistrationReject()
        }
    }

    fun encodeRegistrationReject(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(registrationRejectMessageIdentity.octet.toByte())

        buffer.put(cause5GMM.getIei().toByte())
        buffer.put(cause5GMM.octet.toByte())

        t3346Value?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        t3502Value?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
    }

    fun decodeRegistrationReject(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        registrationRejectMessageIdentity.octet = buffer.get().toUByte()

        cause5GMM = Cause5GMM.newCause5GMM(buffer.get().toUByte())
        cause5GMM.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                RegistrationRejectT3346ValueType -> {
                    t3346Value = T3346Value.newT3346Value(ieiN.toUByte())
                    t3346Value!!.setLen(buffer.get().toUByte())
                    t3346Value!!.octet = buffer.get().toUByte()
                }

                RegistrationRejectT3502ValueType -> {
                    t3502Value = T3502Value.newT3502Value(ieiN.toUByte())
                    t3502Value!!.setLen(buffer.get().toUByte())
                    t3502Value!!.octet = buffer.get().toUByte()
                }

                RegistrationRejectEAPMessageType -> {
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