package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionModificationReject {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONMODIFICATIONREJECTMessageIdentity: PDUSESSIONMODIFICATIONREJECTMessageIdentity = PDUSESSIONMODIFICATIONREJECTMessageIdentity()
    var cause5GSM: Cause5GSM = Cause5GSM()
    var backoffTimerValue: BackoffTimerValue? = null
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null

    companion object {
        const val PDUSessionModificationRejectBackoffTimerValueType: UByte = 0x37u
        const val PDUSessionModificationRejectExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu

        fun NewPDUSessionModificationReject(iei: UByte): PDUSessionModificationReject {
            return PDUSessionModificationReject()
        }
    }

    fun encodePDUSessionModificationReject(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONMODIFICATIONREJECTMessageIdentity.octet.toByte())
        buffer.put(cause5GSM.octet.toByte())

        backoffTimerValue?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        extendedProtocolConfigurationOptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodePDUSessionModificationReject(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONMODIFICATIONREJECTMessageIdentity.octet = buffer.get().toUByte()
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
                PDUSessionModificationRejectBackoffTimerValueType -> {
                    backoffTimerValue = BackoffTimerValue.newBackoffTimerValue(ieiN.toUByte())
                    backoffTimerValue!!.setLen(buffer.get().toUByte())
                    backoffTimerValue!!.octet = buffer.get().toUByte()
                }

                PDUSessionModificationRejectExtendedProtocolConfigurationOptionsType -> {
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