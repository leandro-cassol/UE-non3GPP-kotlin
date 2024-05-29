package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DLNASTransport {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var dLNASTRANSPORTMessageIdentity: DLNASTRANSPORTMessageIdentity = DLNASTRANSPORTMessageIdentity()
    var spareHalfOctetAndPayloadContainerType: SpareHalfOctetAndPayloadContainerType = SpareHalfOctetAndPayloadContainerType()
    var payloadContainer: PayloadContainer = PayloadContainer()
    var pduSessionID2Value: PduSessionID2Value? = null
    var additionalInformation: AdditionalInformation? = null
    var cause5GMM: Cause5GMM? = null
    var backoffTimerValue: BackoffTimerValue? = null

    companion object {
        const val DLNASTransportPduSessionID2ValueType: UByte = 0x12u
        const val DLNASTransportAdditionalInformationType: UByte = 0x24u
        const val DLNASTransportCause5GMMType: UByte = 0x58u
        const val DLNASTransportBackoffTimerValueType: UByte = 0x37u

        fun NewDLNASTransport(iei: UByte): DLNASTransport {
            return DLNASTransport()
        }
    }

    fun encodeDLNASTransport(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(dLNASTRANSPORTMessageIdentity.octet.toByte())
        buffer.put(spareHalfOctetAndPayloadContainerType.octet.toByte())
        buffer.putInt(payloadContainer.getLen().toInt())
        buffer.put(payloadContainer.buffer.toByteArray())

        pduSessionID2Value?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        additionalInformation?.let {
            buffer.put(it.getIei().toByte())
            buffer.putInt(it.getLen().toInt())
            buffer.put(it.buffer.toByteArray())
        }
        cause5GMM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        backoffTimerValue?.let {
            buffer.put(it.getIei().toByte())
            buffer.putInt(it.getLen().toInt())
            buffer.put(it.octet.toByte())
        }
    }

    fun decodeDLNASTransport(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        dLNASTRANSPORTMessageIdentity.octet = buffer.get().toUByte()
        spareHalfOctetAndPayloadContainerType.octet = buffer.get().toUByte()

        payloadContainer.setLen(buffer.short.toUShort())
        val plcBuffer = ByteArray(payloadContainer.getLen().toInt())
        buffer.get(plcBuffer)
        payloadContainer.buffer = plcBuffer.toUByteArray()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                DLNASTransportPduSessionID2ValueType -> {
                    pduSessionID2Value = PduSessionID2Value.newPduSessionID2Value(ieiN.toUByte())
                    pduSessionID2Value!!.octet = buffer.get().toUByte()
                }

                DLNASTransportAdditionalInformationType -> {
                    additionalInformation = AdditionalInformation.newAdditionalInformation(ieiN.toUByte())
                    additionalInformation!!.setLen(buffer.get().toUByte())
                    val aiBuffer = ByteArray(additionalInformation!!.getLen().toInt())
                    buffer.get(aiBuffer)
                    additionalInformation!!.buffer = aiBuffer.toUByteArray()
                }

                DLNASTransportCause5GMMType -> {
                    cause5GMM = Cause5GMM.newCause5GMM(ieiN.toUByte())
                    cause5GMM!!.octet = buffer.get().toUByte()
                }

                DLNASTransportBackoffTimerValueType -> {
                    backoffTimerValue = BackoffTimerValue.newBackoffTimerValue(ieiN.toUByte())
                    backoffTimerValue!!.setLen(buffer.get().toUByte())
                    backoffTimerValue!!.octet = buffer.get().toUByte()
                }
            }
        }
    }
}