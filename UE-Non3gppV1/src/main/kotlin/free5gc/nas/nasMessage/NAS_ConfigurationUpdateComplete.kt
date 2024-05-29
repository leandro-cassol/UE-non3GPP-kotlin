package free5gc.nas.nasMessage

import free5gc.nas.nasType.ConfigurationUpdateCompleteMessageIdentity
import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ConfigurationUpdateComplete {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var configurationUpdateCompleteMessageIdentity: ConfigurationUpdateCompleteMessageIdentity = ConfigurationUpdateCompleteMessageIdentity()

    companion object {
        fun newConfigurationUpdateComplete(iei: UByte): ConfigurationUpdateComplete {
            return ConfigurationUpdateComplete()
        }
    }

    fun encodeConfigurationUpdateComplete(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(configurationUpdateCompleteMessageIdentity.octet.toByte())
    }

    fun decodeConfigurationUpdateComplete(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        configurationUpdateCompleteMessageIdentity.octet = buffer.get().toUByte()

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
                    // Handle other cases
                }
            }
        }
    }
}


