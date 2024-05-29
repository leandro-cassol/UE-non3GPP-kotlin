package free5gc.nas.nasMessage

import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.NotificationResponseMessageIdentity
import free5gc.nas.nasType.PDUSessionStatus
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class NotificationResponse {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var notificationResponseMessageIdentity: NotificationResponseMessageIdentity = NotificationResponseMessageIdentity()
    var pduSessionStatus: PDUSessionStatus? = null

    companion object {
        const val NotificationResponsePDUSessionStatusType: UByte = 0x50u

        fun NewNotificationResponse(iei: UByte): NotificationResponse {
            return NotificationResponse()
        }
    }

    fun encodeNotificationResponse(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(notificationResponseMessageIdentity.octet.toByte())

        pduSessionStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
    }

    fun decodeNotificationResponse(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        notificationResponseMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.hasRemaining()) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                NotificationResponsePDUSessionStatusType -> {
                    pduSessionStatus = PDUSessionStatus.newPDUSessionStatus(ieiN.toUByte())
                    pduSessionStatus!!.setLen(buffer.get().toUByte())
                    val pduBuffer = ByteArray(pduSessionStatus!!.getLen().toInt())
                    buffer.get(pduBuffer)
                    pduSessionStatus!!.buffer = pduBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}