package free5gc.nas.nasMessage

import free5gc.nas.nasType.DeregistrationAcceptMessageIdentity
import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DeregistrationAcceptUETerminatedDeregistration {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var deregistrationAcceptMessageIdentity: DeregistrationAcceptMessageIdentity = DeregistrationAcceptMessageIdentity()

    companion object {
        fun newDeregistrationAcceptUETerminatedDeregistration(iei: UByte): DeregistrationAcceptUETerminatedDeregistration {
            return DeregistrationAcceptUETerminatedDeregistration()
        }
    }

    fun encodeDeregistrationAcceptUETerminatedDeregistration(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(deregistrationAcceptMessageIdentity.octet.toByte())
    }

    fun decodeDeregistrationAcceptUETerminatedDeregistration(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray).order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        deregistrationAcceptMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.hasRemaining()) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                else -> {
                    // Handle other cases or ignore if not applicable
                }
            }
        }
    }
}