package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ServiceReject {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var serviceRejectMessageIdentity: ServiceRejectMessageIdentity = ServiceRejectMessageIdentity()
    var cause5GMM: Cause5GMM = Cause5GMM()
    var pduSessionStatus: PDUSessionStatus? = null
    var t3346Value: T3346Value? = null
    var eapMessage: EAPMessage? = null

    companion object {
        const val ServiceRejectPDUSessionStatusType: UByte = 0x50u
        const val ServiceRejectT3346ValueType: UByte = 0x5Fu
        const val ServiceRejectEAPMessageType: UByte = 0x78u

        fun newServiceReject(iei: UByte): ServiceReject {
            return ServiceReject()
        }
    }

    fun encodeServiceReject(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)

        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(serviceRejectMessageIdentity.octet.toByte())
        buffer.put(cause5GMM.octet.toByte())

        pduSessionStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
        t3346Value?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.octet.toByte())
        }
        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
    }

    fun decodeServiceReject(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        serviceRejectMessageIdentity.octet = buffer.get().toUByte()
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
                ServiceRejectPDUSessionStatusType -> {
                    pduSessionStatus = PDUSessionStatus.newPDUSessionStatus(ieiN.toUByte())
                    pduSessionStatus!!.setLen(buffer.get().toUByte())
                    val pduSSBuffer = ByteArray(pduSessionStatus!!.getLen().toInt())
                    buffer.get(pduSSBuffer)
                    pduSessionStatus!!.buffer = pduSSBuffer.toUByteArray()
                }

                ServiceRejectT3346ValueType -> {
                    t3346Value = T3346Value.newT3346Value(ieiN.toUByte())
                    t3346Value!!.setLen(buffer.get().toUByte())
                    t3346Value!!.octet = buffer.get().toUByte()
                }

                ServiceRejectEAPMessageType -> {
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