package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionReleaseComplete {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONRELEASECOMPLETEMessageIdentity: PDUSESSIONRELEASECOMPLETEMessageIdentity = PDUSESSIONRELEASECOMPLETEMessageIdentity()
    var cause5GSM: Cause5GSM? = null
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null


    companion object {
        const val PDUSessionReleaseCompleteCause5GSMType: UByte = 0x59u
        const val PDUSessionReleaseCompleteExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu

        fun NewPDUSessionReleaseComplete(iei: UByte): PDUSessionReleaseComplete {
            return PDUSessionReleaseComplete()
        }
    }

    fun encodePDUSessionReleaseComplete(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)

        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONRELEASECOMPLETEMessageIdentity.octet.toByte())

        cause5GSM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        extendedProtocolConfigurationOptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodePDUSessionReleaseComplete(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONRELEASECOMPLETEMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                PDUSessionReleaseCompleteCause5GSMType -> {
                    cause5GSM = Cause5GSM.newCause5GSM(ieiN.toUByte())
                    cause5GSM!!.octet = buffer.get().toUByte()
                }

                PDUSessionReleaseCompleteExtendedProtocolConfigurationOptionsType -> {
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