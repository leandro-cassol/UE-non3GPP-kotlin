package free5gc.nas.nasMessage

import free5gc.nas.nasType.Cause5GMM
import free5gc.nas.nasType.ExtendedProtocolDiscriminator
import free5gc.nas.nasType.STATUSMessageIdentity5GMM
import free5gc.nas.nasType.SpareHalfOctetAndSecurityHeaderType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Status5GMM {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var statusMessageIdentity5GMM: STATUSMessageIdentity5GMM = STATUSMessageIdentity5GMM()
    var cause5GMM: Cause5GMM = Cause5GMM()

    companion object {
        fun newStatus5GMM(iei: UByte): Status5GMM {
            return Status5GMM()
        }
    }

    fun encodeStatus5GMM(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(statusMessageIdentity5GMM.octet.toByte())
        buffer.put(cause5GMM.octet.toByte())
    }

    fun decodeStatus5GMM(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray).order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        statusMessageIdentity5GMM.octet = buffer.get().toUByte()
        cause5GMM.octet = buffer.get().toUByte()

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