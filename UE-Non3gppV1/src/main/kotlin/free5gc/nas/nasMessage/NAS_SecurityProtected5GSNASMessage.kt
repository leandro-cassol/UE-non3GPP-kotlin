package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class SecurityProtected5GSNASMessage {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var messageAuthenticationCode: MessageAuthenticationCode = MessageAuthenticationCode()
    var sequenceNumber: SequenceNumber = SequenceNumber()
    var plain5GSNASMessage: Plain5GSNASMessage = Plain5GSNASMessage()

    companion object {
        fun newSecurityProtected5GSNASMessage(iei: UByte): SecurityProtected5GSNASMessage {
            return SecurityProtected5GSNASMessage()
        }
    }

    fun encodeSecurityProtected5GSNASMessage(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(messageAuthenticationCode.octet.toByteArray())
        buffer.put(sequenceNumber.octet.toByte())
        //buffer.put(plain5GSNASMessage)
    }

    fun decodeSecurityProtected5GSNASMessage(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()

        val auxByteArray = ByteArray(4)
        buffer.get(auxByteArray)
        messageAuthenticationCode.octet = auxByteArray.toUByteArray()

        sequenceNumber.octet = buffer.get().toUByte()
        //buffer.get(plain5GSNASMessage)

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