package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionAuthenticationComplete {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONAUTHENTICATIONCOMPLETEMessageIdentity: PDUSESSIONAUTHENTICATIONCOMPLETEMessageIdentity = PDUSESSIONAUTHENTICATIONCOMPLETEMessageIdentity()
    var eapMessage: EAPMessage = EAPMessage()
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null

    companion object {
        const val PDUSessionAuthenticationCompleteExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu

        fun NewPDUSessionAuthenticationComplete(iei: UByte): PDUSessionAuthenticationComplete {
            return PDUSessionAuthenticationComplete()
        }
    }

    fun encodePDUSessionAuthenticationComplete(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONAUTHENTICATIONCOMPLETEMessageIdentity.octet.toByte())

        buffer.putShort(eapMessage.getLen().toShort())
        buffer.put(eapMessage.buffer.toByteArray())

        extendedProtocolConfigurationOptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodePDUSessionAuthenticationComplete(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray).order(ByteOrder.BIG_ENDIAN)
        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONAUTHENTICATIONCOMPLETEMessageIdentity.octet = buffer.get().toUByte()

        eapMessage.setLen(buffer.short.toUShort())
        val eapBuffer = ByteArray(eapMessage.getLen().toInt())
        buffer.get(eapBuffer)
        eapMessage.buffer = eapBuffer.toUByteArray()

        while (buffer.hasRemaining()) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                PDUSessionAuthenticationCompleteExtendedProtocolConfigurationOptionsType -> {
                    extendedProtocolConfigurationOptions = ExtendedProtocolConfigurationOptions.newExtendedProtocolConfigurationOptions(ieiN.toUByte())
                    extendedProtocolConfigurationOptions!!.setLen(buffer.short.toUShort())

                    val auxBuffer = ByteArray(extendedProtocolConfigurationOptions!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    extendedProtocolConfigurationOptions!!.buffer = auxBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}