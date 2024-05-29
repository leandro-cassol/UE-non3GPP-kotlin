package free5gc.nas.nasMessage

import java.nio.ByteBuffer
import java.nio.ByteOrder

import free5gc.nas.nasType.*

class PDUSessionReleaseRequest {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONRELEASEREQUESTMessageIdentity: PDUSESSIONRELEASEREQUESTMessageIdentity = PDUSESSIONRELEASEREQUESTMessageIdentity()
    var cause5GSM: Cause5GSM? = null
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null


    companion object {
        const val PDUSessionReleaseRequestCause5GSMType: UByte = 0x59u
        const val PDUSessionReleaseRequestExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu

        fun NewPDUSessionReleaseRequest(iei: UByte): PDUSessionReleaseRequest {
            return PDUSessionReleaseRequest()
        }
    }

    fun encodePDUSessionReleaseRequest(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)

        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONRELEASEREQUESTMessageIdentity.octet.toByte())

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

    fun decodePDUSessionReleaseRequest(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONRELEASEREQUESTMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.hasRemaining()) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                PDUSessionReleaseRequestCause5GSMType -> {
                    cause5GSM = Cause5GSM.newCause5GSM(ieiN.toUByte())
                    cause5GSM!!.octet = buffer.get().toUByte()
                }

                PDUSessionReleaseRequestExtendedProtocolConfigurationOptionsType -> {
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