package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Status5GSM {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var statusMessageIdentity5GSM: STATUSMessageIdentity5GSM = STATUSMessageIdentity5GSM()
    var cause5GSM: Cause5GSM = Cause5GSM()

    companion object {
        fun newStatus5GSM(iei: UByte): Status5GSM {
            return Status5GSM()
        }
    }

    fun encodeStatus5GSM(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(statusMessageIdentity5GSM.octet.toByte())
        buffer.put(cause5GSM.octet.toByte())
    }

    fun decodeStatus5GSM(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        statusMessageIdentity5GSM.octet = buffer.get().toUByte()
        cause5GSM.octet = buffer.get().toUByte()

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