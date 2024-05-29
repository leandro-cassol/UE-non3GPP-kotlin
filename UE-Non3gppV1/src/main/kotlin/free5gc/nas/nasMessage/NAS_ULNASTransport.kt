package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ULNASTransport {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var uLNASTRANSPORTMessageIdentity: ULNASTRANSPORTMessageIdentity = ULNASTRANSPORTMessageIdentity()
    var spareHalfOctetAndPayloadContainerType: SpareHalfOctetAndPayloadContainerType = SpareHalfOctetAndPayloadContainerType()
    var payloadContainer: PayloadContainer = PayloadContainer()
    var pduSessionID2Value: PduSessionID2Value? = null
    var oldPDUSessionID: OldPDUSessionID? = null
    var requestType: RequestType? = null
    var sNSSAI: SNSSAI? = null
    var dnn: DNN? = null
    var additionalInformation: AdditionalInformation? = null

    companion object {
        const val ULNASTransportPduSessionID2ValueType: UByte = 0x12u
        const val ULNASTransportOldPDUSessionIDType: UByte = 0x59u
        const val ULNASTransportRequestTypeType: UByte = 0x08u
        const val ULNASTransportSNSSAIType: UByte = 0x22u
        const val ULNASTransportDNNType: UByte = 0x25u
        const val ULNASTransportAdditionalInformationType: UByte = 0x24u

        fun newULNASTransport(iei: UByte): ULNASTransport {
            return ULNASTransport()
        }
    }

    fun encodeULNASTransport(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(uLNASTRANSPORTMessageIdentity.octet.toByte())
        buffer.put(spareHalfOctetAndPayloadContainerType.octet.toByte())

        buffer.putShort(payloadContainer.getLen().toShort())
        buffer.put(payloadContainer.buffer.toByteArray())

        pduSessionID2Value?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        oldPDUSessionID?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        requestType?.let {
            buffer.put(it.octet.toByte())
        }
        sNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        dnn?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray().copyOfRange(0, it.getLen().toInt()))
        }
        additionalInformation?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodeULNASTransport(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        uLNASTRANSPORTMessageIdentity.octet = buffer.get().toUByte()
        spareHalfOctetAndPayloadContainerType.octet = buffer.get().toUByte()

        payloadContainer.setLen(buffer.short.toUShort())
        val plcBuffer = ByteArray(payloadContainer.getLen().toInt())
        buffer.get(plcBuffer)
        payloadContainer.buffer = plcBuffer.toUByteArray()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF // Convert to UInt to match Go's uint8
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                ULNASTransportPduSessionID2ValueType -> {
                    pduSessionID2Value = PduSessionID2Value.newPduSessionID2Value(ieiN.toUByte())
                    pduSessionID2Value!!.octet = buffer.get().toUByte()
                }

                ULNASTransportOldPDUSessionIDType -> {
                    oldPDUSessionID = OldPDUSessionID.newOldPDUSessionID(ieiN.toUByte())
                    oldPDUSessionID!!.octet = buffer.get().toUByte()
                }

                ULNASTransportRequestTypeType -> {
                    requestType = RequestType.newRequestType(ieiN.toUByte())
                    requestType!!.octet = ieiN.toUByte()
                }

                ULNASTransportSNSSAIType -> {
                    sNSSAI = SNSSAI.newSNSSAI(ieiN.toUByte())
                    sNSSAI!!.setLen(buffer.get().toUByte())
                    val sNBuffer = ByteArray(sNSSAI!!.getLen().toInt())
                    buffer.get(sNBuffer)
                    sNSSAI!!.octet = sNBuffer.toUByteArray()
                }

                ULNASTransportDNNType -> {
                    dnn = DNN.newDNN(ieiN.toUByte())
                    dnn!!.setLen(buffer.get().toUByte())
                    val dnnBuffer = ByteArray(dnn!!.getLen().toInt())
                    buffer.get(dnnBuffer)
                    dnn!!.buffer = dnnBuffer.toUByteArray()
                }

                ULNASTransportAdditionalInformationType -> {
                    additionalInformation = AdditionalInformation.newAdditionalInformation(ieiN.toUByte())
                    additionalInformation!!.setLen(buffer.get().toUByte())
                    val aiBuffer = ByteArray(additionalInformation!!.getLen().toInt())
                    buffer.get(aiBuffer)
                    additionalInformation!!.buffer = aiBuffer.toUByteArray()
                }
            }
        }
    }
}