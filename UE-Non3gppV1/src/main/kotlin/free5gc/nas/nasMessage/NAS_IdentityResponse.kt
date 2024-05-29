package free5gc.nas.nasMessage

import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.IdentityResponseMessageIdentity
import free5gc.nas.nasType.MobileIdentity
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class IdentityResponse {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var identityResponseMessageIdentity: IdentityResponseMessageIdentity = IdentityResponseMessageIdentity()
    var mobileIdentity: MobileIdentity = MobileIdentity()

    companion object {
        fun newIdentityResponse(iei: UByte): IdentityResponse {
            return IdentityResponse()
        }
    }

    fun encodeIdentityResponse(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(identityResponseMessageIdentity.octet.toByte())
        buffer.put(mobileIdentity.getLen().toByte())
        buffer.put(mobileIdentity.buffer.toByteArray())
    }

    fun decodeIdentityResponse(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray).order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        identityResponseMessageIdentity.octet = buffer.get().toUByte()

        mobileIdentity.setLen(buffer.short.toUShort())
        val miBuffer = ByteArray(mobileIdentity.getLen().toInt())
        buffer.get(miBuffer)
        mobileIdentity.buffer = miBuffer.toUByteArray()

        while (buffer.remaining() > 0) {
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