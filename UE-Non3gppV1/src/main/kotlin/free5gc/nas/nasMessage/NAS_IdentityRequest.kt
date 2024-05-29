package free5gc.nas.nasMessage

import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.IdentityRequestMessageIdentity
import free5gc.nas.nasType.SpareHalfOctetAndIdentityType
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class IdentityRequest {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var identityRequestMessageIdentity: IdentityRequestMessageIdentity = IdentityRequestMessageIdentity()
    var spareHalfOctetAndIdentityType: SpareHalfOctetAndIdentityType = SpareHalfOctetAndIdentityType()

    companion object {
        fun newIdentityRequest(iei: UByte): IdentityRequest {
            return IdentityRequest()
        }
    }

    fun encodeIdentityRequest(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(identityRequestMessageIdentity.octet.toByte())
        buffer.put(spareHalfOctetAndIdentityType.octet.toByte())
    }

    fun decodeIdentityRequest(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        identityRequestMessageIdentity.octet = buffer.get().toUByte()
        spareHalfOctetAndIdentityType.octet = buffer.get().toUByte()

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
                }
            }
        }
    }
}
