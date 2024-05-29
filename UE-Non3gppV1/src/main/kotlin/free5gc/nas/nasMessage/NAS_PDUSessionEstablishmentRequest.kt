package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionEstablishmentRequest {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONESTABLISHMENTREQUESTMessageIdentity: PDUSESSIONESTABLISHMENTREQUESTMessageIdentity = PDUSESSIONESTABLISHMENTREQUESTMessageIdentity()
    var integrityProtectionMaximumDataRate: IntegrityProtectionMaximumDataRate = IntegrityProtectionMaximumDataRate()
    var pDUSessionType: PDUSessionType? = null
    var sscMode: SSCMode? = null
    var capability5GSM: Capability5GSM? = null
    var maximumNumberOfSupportedPacketFilters: MaximumNumberOfSupportedPacketFilters? = null
    var alwaysonPDUSessionRequested: AlwaysonPDUSessionRequested? = null
    var sMPDUDNRequestContainer: SMPDUDNRequestContainer? = null
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null

    fun encodePDUSessionEstablishmentRequest(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)

        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONESTABLISHMENTREQUESTMessageIdentity.octet.toByte())
        buffer.put(integrityProtectionMaximumDataRate.octet.toByteArray())

        pDUSessionType?.let {
            buffer.put(it.octet.toByte())
        }
        sscMode?.let {
            buffer.put(it.octet.toByte())
        }
        capability5GSM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        maximumNumberOfSupportedPacketFilters?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByteArray())
        }
        alwaysonPDUSessionRequested?.let {
            buffer.put(it.octet.toByte())
        }
        sMPDUDNRequestContainer?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        extendedProtocolConfigurationOptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodePDUSessionEstablishmentRequest(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONESTABLISHMENTREQUESTMessageIdentity.octet = buffer.get().toUByte()

        val ipmOctets = ByteArray(integrityProtectionMaximumDataRate.octet.size)
        buffer.get(ipmOctets)
        integrityProtectionMaximumDataRate.octet = ipmOctets.toUByteArray()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                PDUSessionEstablishmentRequestPDUSessionTypeType -> {
                    pDUSessionType = PDUSessionType.newPDUSessionType(ieiN.toUByte())
                    pDUSessionType!!.octet = ieiN.toUByte()
                }

                PDUSessionEstablishmentRequestSSCModeType -> {
                    sscMode = SSCMode.newSSCMode(ieiN.toUByte())
                    sscMode!!.octet = ieiN.toUByte()
                }

                PDUSessionEstablishmentRequestCapability5GSMType -> {
                    capability5GSM = Capability5GSM.newCapability5GSM(ieiN.toUByte())
                    capability5GSM!!.setLen(buffer.get().toUByte())

                    val auxBuffer = ByteArray(capability5GSM!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    capability5GSM!!.octet = auxBuffer.toUByteArray()
                }

                PDUSessionEstablishmentRequestMaximumNumberOfSupportedPacketFiltersType -> {
                    maximumNumberOfSupportedPacketFilters = MaximumNumberOfSupportedPacketFilters.newMaximumNumberOfSupportedPacketFilters(ieiN.toUByte())
                    val octets = ByteArray(maximumNumberOfSupportedPacketFilters!!.octet.size)
                    buffer.get(octets)
                    maximumNumberOfSupportedPacketFilters!!.octet = octets.toUByteArray()
                }

                PDUSessionEstablishmentRequestAlwaysonPDUSessionRequestedType -> {
                    alwaysonPDUSessionRequested = AlwaysonPDUSessionRequested.newAlwaysonPDUSessionRequested(ieiN.toUByte())
                    alwaysonPDUSessionRequested!!.octet = ieiN.toUByte()
                }

                PDUSessionEstablishmentRequestSMPDUDNRequestContainerType -> {
                    sMPDUDNRequestContainer = SMPDUDNRequestContainer.newSMPDUDNRequestContainer(ieiN.toUByte())
                    sMPDUDNRequestContainer!!.setLen(buffer.get().toUByte())

                    val auxBuffer = ByteArray(sMPDUDNRequestContainer!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    sMPDUDNRequestContainer!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionEstablishmentRequestExtendedProtocolConfigurationOptionsType -> {
                    extendedProtocolConfigurationOptions = ExtendedProtocolConfigurationOptions.newExtendedProtocolConfigurationOptions(ieiN.toUByte())
                    extendedProtocolConfigurationOptions!!.setLen(buffer.short.toUShort())

                    val auxBuffer = ByteArray(extendedProtocolConfigurationOptions!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    extendedProtocolConfigurationOptions!!.buffer = auxBuffer.toUByteArray()
                }
                else -> {}
            }
        }
    }

    companion object {
        fun NewPDUSessionEstablishmentRequest(iei: UByte): PDUSessionEstablishmentRequest {
            return PDUSessionEstablishmentRequest()
        }

        const val PDUSessionEstablishmentRequestPDUSessionTypeType: UByte = 0x09u
        const val PDUSessionEstablishmentRequestSSCModeType: UByte = 0x0Au
        const val PDUSessionEstablishmentRequestCapability5GSMType: UByte = 0x28u
        const val PDUSessionEstablishmentRequestMaximumNumberOfSupportedPacketFiltersType: UByte = 0x55u
        const val PDUSessionEstablishmentRequestAlwaysonPDUSessionRequestedType: UByte = 0x0Bu
        const val PDUSessionEstablishmentRequestSMPDUDNRequestContainerType: UByte = 0x39u
        const val PDUSessionEstablishmentRequestExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu
    }
}