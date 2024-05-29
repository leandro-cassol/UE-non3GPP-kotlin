package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ServiceRequest {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var serviceRequestMessageIdentity: ServiceRequestMessageIdentity = ServiceRequestMessageIdentity()
    var serviceTypeAndNgksi: ServiceTypeAndNgksi = ServiceTypeAndNgksi()
    var tmsi5GS: TMSI5GS = TMSI5GS()
    var uplinkDataStatus: UplinkDataStatus? = null
    var pduSessionStatus: PDUSessionStatus? = null
    var allowedPDUSessionStatus: AllowedPDUSessionStatus? = null
    var nasMessageContainer: NASMessageContainer? = null

    companion object {
        const val ServiceRequestUplinkDataStatusType: UByte = 0x40u
        const val ServiceRequestPDUSessionStatusType: UByte = 0x50u
        const val ServiceRequestAllowedPDUSessionStatusType: UByte = 0x25u
        const val ServiceRequestNASMessageContainerType: UByte = 0x71u

        fun newServiceRequest(iei: UByte): ServiceRequest {
            return ServiceRequest()
        }
    }

    fun encodeServiceRequest(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(serviceRequestMessageIdentity.octet.toByte())
        buffer.put(serviceTypeAndNgksi.octet.toByte())

        buffer.put(tmsi5GS.getLen().toByte())
        buffer.put(tmsi5GS.octet.toByteArray(), 0, tmsi5GS.getLen().toInt())

        uplinkDataStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        pduSessionStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        allowedPDUSessionStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        nasMessageContainer?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodeServiceRequest(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        serviceRequestMessageIdentity.octet = buffer.get().toUByte()
        serviceTypeAndNgksi.octet = buffer.get().toUByte()

        tmsi5GS.len = buffer.short.toUShort()
        tmsi5GS.setLen(tmsi5GS.getLen())
        buffer.get(tmsi5GS.octet.toByteArray(), 0, tmsi5GS.getLen().toInt())

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                ServiceRequestUplinkDataStatusType -> {
                    uplinkDataStatus = UplinkDataStatus.newUplinkDataStatus(ieiN.toUByte())
                    uplinkDataStatus!!.setLen(buffer.get().toUByte())

                    val upBuffer = ByteArray(uplinkDataStatus!!.getLen().toInt())
                    buffer.get(upBuffer)
                    uplinkDataStatus!!.buffer = upBuffer.toUByteArray()
                }

                ServiceRequestPDUSessionStatusType -> {
                    pduSessionStatus = PDUSessionStatus.newPDUSessionStatus(ieiN.toUByte())
                    pduSessionStatus!!.setLen(buffer.get().toUByte())

                    val pduBuffer = ByteArray(pduSessionStatus!!.getLen().toInt())
                    buffer.get(pduBuffer)
                    pduSessionStatus!!.buffer = pduBuffer.toUByteArray()
                }

                ServiceRequestAllowedPDUSessionStatusType -> {
                    allowedPDUSessionStatus = AllowedPDUSessionStatus.newAllowedPDUSessionStatus(ieiN.toUByte())
                    allowedPDUSessionStatus!!.setLen(buffer.get().toUByte())

                    val allowedBuffer = ByteArray(allowedPDUSessionStatus!!.getLen().toInt())
                    buffer.get(allowedBuffer)
                    allowedPDUSessionStatus!!.buffer = allowedBuffer.toUByteArray()
                }

                ServiceRequestNASMessageContainerType -> {
                    nasMessageContainer = NASMessageContainer.newNASMessageContainer(ieiN.toUByte())
                    nasMessageContainer!!.setLen(buffer.short.toUShort())
                    val nasBuffer = ByteArray(nasMessageContainer!!.getLen().toInt())
                    buffer.get(nasBuffer)
                    nasMessageContainer!!.buffer = nasBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}