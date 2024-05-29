package free5gc.nas.nasMessage

import free5gc.nas.nasType.DeregistrationAcceptMessageIdentity
import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DeregistrationAcceptUEOriginatingDeregistration {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var deregistrationAcceptMessageIdentity: DeregistrationAcceptMessageIdentity = DeregistrationAcceptMessageIdentity()

    companion object {
        fun newDeregistrationAcceptUEOriginatingDeregistration(iei: UByte): DeregistrationAcceptUEOriginatingDeregistration {
            return DeregistrationAcceptUEOriginatingDeregistration()
        }
    }

    fun encodeDeregistrationAcceptUEOriginatingDeregistration(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(deregistrationAcceptMessageIdentity.octet.toByte())
    }

    fun decodeDeregistrationAcceptUEOriginatingDeregistration(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
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
                    // Handle default case or unknown IEI
                }
            }
        }
    }
}


