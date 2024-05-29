package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionModificationCommandReject {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONMODIFICATIONCOMMANDREJECTMessageIdentity: PDUSESSIONMODIFICATIONCOMMANDREJECTMessageIdentity = PDUSESSIONMODIFICATIONCOMMANDREJECTMessageIdentity()
    var cause5GSM: Cause5GSM = Cause5GSM()
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null

    companion object {
        const val PDUSessionModificationCommandRejectExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu

        fun NewPDUSessionModificationCommandReject(iei: UByte): PDUSessionModificationCommandReject {
            return PDUSessionModificationCommandReject()
        }
    }

    fun encodePDUSessionModificationCommandReject(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONMODIFICATIONCOMMANDREJECTMessageIdentity.octet.toByte())
        buffer.put(cause5GSM.octet.toByte())

        extendedProtocolConfigurationOptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodePDUSessionModificationCommandReject(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONMODIFICATIONCOMMANDREJECTMessageIdentity.octet = buffer.get().toUByte()
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
                PDUSessionModificationCommandRejectExtendedProtocolConfigurationOptionsType -> {
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