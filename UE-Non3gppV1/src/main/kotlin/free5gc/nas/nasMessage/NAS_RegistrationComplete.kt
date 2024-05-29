package free5gc.nas.nasMessage

import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.RegistrationCompleteMessageIdentity
import free5gc.nas.nasType.SORTransparentContainer
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RegistrationComplete {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var registrationCompleteMessageIdentity: RegistrationCompleteMessageIdentity = RegistrationCompleteMessageIdentity()
    var sorTransparentContainer: SORTransparentContainer? = null

    companion object {
        const val RegistrationCompleteSORTransparentContainerType: UByte = 0x73u

        fun newRegistrationComplete(iei: UByte): RegistrationComplete {
            return RegistrationComplete()
        }
    }

    fun encodeRegistrationComplete(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(registrationCompleteMessageIdentity.octet.toByte())

        sorTransparentContainer?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodeRegistrationComplete(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        registrationCompleteMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                RegistrationCompleteSORTransparentContainerType -> {
                    sorTransparentContainer = SORTransparentContainer.newSORTransparentContainer(ieiN.toUByte())
                    sorTransparentContainer!!.setLen(buffer.short.toUShort())

                    val stBuffer = ByteArray(sorTransparentContainer!!.getLen().toInt())
                    buffer.get(stBuffer)
                    sorTransparentContainer!!.buffer = stBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}