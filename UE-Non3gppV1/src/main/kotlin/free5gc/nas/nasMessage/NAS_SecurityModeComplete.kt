package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class SecurityModeComplete {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var securityModeCompleteMessageIdentity: SecurityModeCompleteMessageIdentity = SecurityModeCompleteMessageIdentity()
    var imeisv: IMEISV? = null
    var nasMessageContainer: NASMessageContainer? = null

    companion object {
        const val SecurityModeCompleteIMEISVType: UByte = 0x77u
        const val SecurityModeCompleteNASMessageContainerType: UByte = 0x71u

        fun NewSecurityModeComplete(iei: UByte): SecurityModeComplete {
            return SecurityModeComplete()
        }
    }

    fun encodeSecurityModeComplete(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(securityModeCompleteMessageIdentity.octet.toByte())

        imeisv?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        nasMessageContainer?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
    }

    fun decodeSecurityModeComplete(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        securityModeCompleteMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                SecurityModeCompleteIMEISVType -> {
                    imeisv = IMEISV.newIMEISV(ieiN.toUByte())
                    imeisv!!.setLen(buffer.getShort().toUShort())

                    val auxByteArray = ByteArray(imeisv!!.getLen().toInt())
                    buffer.get(auxByteArray)
                    imeisv!!.octet = auxByteArray.toUByteArray()
                }

                SecurityModeCompleteNASMessageContainerType -> {
                    nasMessageContainer = NASMessageContainer.newNASMessageContainer(ieiN.toUByte())
                    nasMessageContainer!!.setLen(buffer.short.toUShort())
                    val auxByteArray = ByteArray(nasMessageContainer!!.getLen().toInt())
                    buffer.get(auxByteArray)
                    nasMessageContainer!!.buffer = auxByteArray.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}