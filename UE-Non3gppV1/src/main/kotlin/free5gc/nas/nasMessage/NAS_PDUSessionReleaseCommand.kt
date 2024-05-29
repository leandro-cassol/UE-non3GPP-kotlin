package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionReleaseCommand {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONRELEASECOMMANDMessageIdentity: PDUSESSIONRELEASECOMMANDMessageIdentity = PDUSESSIONRELEASECOMMANDMessageIdentity()
    var cause5GSM: Cause5GSM = Cause5GSM()
    var backoffTimerValue: BackoffTimerValue? = null
    var eapMessage: EAPMessage? = null
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null

    companion object {
        const val PDUSessionReleaseCommandBackoffTimerValueType: UByte = 0x37u
        const val PDUSessionReleaseCommandEAPMessageType: UByte = 0x78u
        const val PDUSessionReleaseCommandExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu

        fun newPDUSessionReleaseCommand(iei: UByte): PDUSessionReleaseCommand {
            return PDUSessionReleaseCommand()
        }
    }

    fun encodePDUSessionReleaseCommand(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONRELEASECOMMANDMessageIdentity.octet.toByte())
        buffer.put(cause5GSM.octet.toByte())

        backoffTimerValue?.let {
            buffer.put(it.getIei().toByte())
            buffer.putInt(it.getLen().toInt())
            buffer.put(it.octet.toByte())
        }
        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        extendedProtocolConfigurationOptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodePDUSessionReleaseCommand(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONRELEASECOMMANDMessageIdentity.octet = buffer.get().toUByte()
        cause5GSM.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                PDUSessionReleaseCommandBackoffTimerValueType -> {
                    backoffTimerValue = BackoffTimerValue.newBackoffTimerValue(ieiN.toUByte())
                    backoffTimerValue!!.setLen(buffer.get().toUByte())
                    backoffTimerValue!!.octet = buffer.get().toUByte()
                }

                PDUSessionReleaseCommandEAPMessageType -> {
                    eapMessage = EAPMessage.newEAPMessage(ieiN.toUByte())
                    eapMessage!!.setLen(buffer.short.toUShort())
                    val eapBuffer = ByteArray(eapMessage!!.getLen().toInt())
                    buffer.get(eapBuffer)
                    eapMessage!!.buffer = eapBuffer.toUByteArray()
                }

                PDUSessionReleaseCommandExtendedProtocolConfigurationOptionsType -> {
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