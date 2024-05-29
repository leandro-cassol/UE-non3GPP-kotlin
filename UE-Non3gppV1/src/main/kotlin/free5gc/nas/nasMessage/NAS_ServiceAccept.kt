package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ServiceAccept {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var serviceAcceptMessageIdentity: ServiceAcceptMessageIdentity = ServiceAcceptMessageIdentity()
    var pduSessionStatus: PDUSessionStatus? = null
    var pduSessionReactivationResult: PDUSessionReactivationResult? = null
    var pduSessionReactivationResultErrorCause: PDUSessionReactivationResultErrorCause? = null
    var eapMessage: EAPMessage? = null

    companion object {
        const val ServiceAcceptPDUSessionStatusType: UByte = 0x50u
        const val ServiceAcceptPDUSessionReactivationResultType: UByte = 0x26u
        const val ServiceAcceptPDUSessionReactivationResultErrorCauseType: UByte = 0x72u
        const val ServiceAcceptEAPMessageType: UByte = 0x78u

        fun newServiceAccept(iei: UByte): ServiceAccept {
            return ServiceAccept()
        }
    }

    fun encodeServiceAccept(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(serviceAcceptMessageIdentity.octet.toByte())

        pduSessionStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }

        pduSessionReactivationResult?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }

        pduSessionReactivationResultErrorCause?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }

        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }

    }

    fun decodeServiceAccept(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        serviceAcceptMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                ServiceAcceptPDUSessionStatusType -> {
                    pduSessionStatus = PDUSessionStatus.newPDUSessionStatus(ieiN.toUByte())
                    pduSessionStatus!!.setLen(buffer.get().toUByte())
                    val pduSSBuffer = ByteArray(pduSessionStatus!!.getLen().toInt())
                    buffer.get(pduSSBuffer)
                    pduSessionStatus!!.buffer = pduSSBuffer.toUByteArray()
                }

                ServiceAcceptPDUSessionReactivationResultType -> {
                    pduSessionReactivationResult = PDUSessionReactivationResult.newPDUSessionReactivationResult(ieiN.toUByte())
                    pduSessionReactivationResult!!.setLen(buffer.get().toUByte())
                    val pduSRRBuffer = ByteArray(pduSessionReactivationResult!!.getLen().toInt())
                    buffer.get(pduSRRBuffer)
                    pduSessionReactivationResult!!.buffer = pduSRRBuffer.toUByteArray()
                }

                ServiceAcceptPDUSessionReactivationResultErrorCauseType -> {
                    pduSessionReactivationResultErrorCause = PDUSessionReactivationResultErrorCause.newPDUSessionReactivationResultErrorCause(ieiN.toUByte())
                    pduSessionReactivationResultErrorCause!!.setLen(buffer.short.toUShort())
                    val pduSRRECBuffer = ByteArray(pduSessionReactivationResultErrorCause!!.getLen().toInt())
                    buffer.get(pduSRRECBuffer)
                    pduSessionReactivationResultErrorCause!!.buffer = pduSRRECBuffer.toUByteArray()
                }

                ServiceAcceptEAPMessageType -> {
                    eapMessage = EAPMessage.newEAPMessage(ieiN.toUByte())
                    eapMessage!!.setLen(buffer.short.toUShort())
                    val eapBuffer = ByteArray(eapMessage!!.getLen().toInt())
                    buffer.get(eapBuffer)
                    eapMessage!!.buffer = eapBuffer.toUByteArray()
                }
            }
        }
    }
}