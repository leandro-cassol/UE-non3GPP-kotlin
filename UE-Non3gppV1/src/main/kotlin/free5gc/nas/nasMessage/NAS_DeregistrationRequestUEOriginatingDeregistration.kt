package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DeregistrationRequestUEOriginatingDeregistration {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var deregistrationRequestMessageIdentity: DeregistrationRequestMessageIdentity = DeregistrationRequestMessageIdentity()
    var ngksiAndDeregistrationType: NgksiAndDeregistrationType = NgksiAndDeregistrationType.newNgksiAndDeregistrationType()
    var mobileIdentity5GS: MobileIdentity5GS = MobileIdentity5GS()

    companion object {
        fun newDeregistrationRequestUEOriginatingDeregistration(iei: UByte): DeregistrationRequestUEOriginatingDeregistration {
            return DeregistrationRequestUEOriginatingDeregistration()
        }
    }

    fun encodeDeregistrationRequestUEOriginatingDeregistration(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(deregistrationRequestMessageIdentity.octet.toByte())
        buffer.put(ngksiAndDeregistrationType.octet.toByte())
        buffer.put(mobileIdentity5GS.getLen().toByte())
        buffer.put(mobileIdentity5GS.buffer.toByteArray())
    }

    fun decodeDeregistrationRequestUEOriginatingDeregistration(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        deregistrationRequestMessageIdentity.octet = buffer.get().toUByte()
        ngksiAndDeregistrationType.octet = buffer.get().toUByte()

        mobileIdentity5GS.setLen(buffer.short.toUShort())
        val auxByteArray = ByteArray(mobileIdentity5GS.getLen().toInt())
        buffer.get(auxByteArray)
        mobileIdentity5GS.buffer = auxByteArray.toUByteArray()

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