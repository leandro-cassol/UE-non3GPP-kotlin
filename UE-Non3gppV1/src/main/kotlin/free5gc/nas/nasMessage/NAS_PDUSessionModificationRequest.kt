package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PDUSessionModificationRequest {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var pduSessionID: PDUSessionID = PDUSessionID()
    var pti: PTI = PTI()
    var pDUSESSIONMODIFICATIONREQUESTMessageIdentity: PDUSESSIONMODIFICATIONREQUESTMessageIdentity = PDUSESSIONMODIFICATIONREQUESTMessageIdentity()
    var capability5GSM: Capability5GSM? = null
    var cause5GSM: Cause5GSM? = null
    var maximumNumberOfSupportedPacketFilters: MaximumNumberOfSupportedPacketFilters? = null
    var alwaysonPDUSessionRequested: AlwaysonPDUSessionRequested? = null
    var integrityProtectionMaximumDataRate: IntegrityProtectionMaximumDataRate? = null
    var requestedQosRules: RequestedQosRules? = null
    var requestedQosFlowDescriptions: RequestedQosFlowDescriptions? = null
    var mappedEPSBearerContexts: MappedEPSBearerContexts? = null
    var extendedProtocolConfigurationOptions: ExtendedProtocolConfigurationOptions? = null

    fun encodePDUSessionModificationRequest(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)

        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(pduSessionID.octet.toByte())
        buffer.put(pti.octet.toByte())
        buffer.put(pDUSESSIONMODIFICATIONREQUESTMessageIdentity.octet.toByte())

        capability5GSM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        cause5GSM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByte())
        }
        maximumNumberOfSupportedPacketFilters?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByteArray())
        }
        alwaysonPDUSessionRequested?.let {
            buffer.put(it.octet.toByte())
        }
        integrityProtectionMaximumDataRate?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByteArray())
        }
        requestedQosRules?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        requestedQosFlowDescriptions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        mappedEPSBearerContexts?.let {
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

    fun decodePDUSessionModificationRequest(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        pduSessionID.octet = buffer.get().toUByte()
        pti.octet = buffer.get().toUByte()
        pDUSESSIONMODIFICATIONREQUESTMessageIdentity.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                PDUSessionModificationRequestCapability5GSMType -> {
                    capability5GSM = Capability5GSM.newCapability5GSM(ieiN.toUByte())
                    capability5GSM!!.setLen(buffer.get().toUByte())

                    val auxBuffer = ByteArray(capability5GSM!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    capability5GSM!!.octet = auxBuffer.toUByteArray()
                }

                PDUSessionModificationRequestCause5GSMType -> {
                    cause5GSM = Cause5GSM.newCause5GSM(ieiN.toUByte())
                    cause5GSM!!.octet = buffer.get().toUByte()
                }

                PDUSessionModificationRequestMaximumNumberOfSupportedPacketFiltersType -> {
                    maximumNumberOfSupportedPacketFilters = MaximumNumberOfSupportedPacketFilters.newMaximumNumberOfSupportedPacketFilters(ieiN.toUByte())

                    val auxBuffer = ByteArray(maximumNumberOfSupportedPacketFilters!!.octet.size)
                    buffer.get(auxBuffer)
                    maximumNumberOfSupportedPacketFilters!!.octet = auxBuffer.toUByteArray()
                }

                PDUSessionModificationRequestAlwaysonPDUSessionRequestedType -> {
                    alwaysonPDUSessionRequested = AlwaysonPDUSessionRequested.newAlwaysonPDUSessionRequested(ieiN.toUByte())
                    alwaysonPDUSessionRequested!!.octet = ieiN.toUByte()
                }

                PDUSessionModificationRequestIntegrityProtectionMaximumDataRateType -> {
                    integrityProtectionMaximumDataRate = IntegrityProtectionMaximumDataRate.newIntegrityProtectionMaximumDataRate(ieiN.toUByte())

                    val auxBuffer = ByteArray(integrityProtectionMaximumDataRate!!.octet.size)
                    buffer.get(auxBuffer)
                    integrityProtectionMaximumDataRate!!.octet = auxBuffer.toUByteArray()
                }

                PDUSessionModificationRequestRequestedQosRulesType -> {
                    requestedQosRules = RequestedQosRules.newRequestedQosRules(ieiN.toUByte())
                    requestedQosRules!!.setLen(buffer.short.toUShort())
                    val auxBuffer = ByteArray(requestedQosRules!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    requestedQosRules!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionModificationRequestRequestedQosFlowDescriptionsType -> {
                    requestedQosFlowDescriptions = RequestedQosFlowDescriptions.newRequestedQosFlowDescriptions(ieiN.toUByte())
                    requestedQosFlowDescriptions!!.setLen(buffer.short.toUShort())
                    val auxBuffer = ByteArray(requestedQosFlowDescriptions!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    requestedQosFlowDescriptions!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionModificationRequestMappedEPSBearerContextsType -> {
                    mappedEPSBearerContexts = MappedEPSBearerContexts.newMappedEPSBearerContexts(ieiN.toUByte())
                    mappedEPSBearerContexts!!.setLen(buffer.short.toUShort())
                    val auxBuffer = ByteArray(mappedEPSBearerContexts!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    mappedEPSBearerContexts!!.buffer = auxBuffer.toUByteArray()
                }

                PDUSessionModificationRequestExtendedProtocolConfigurationOptionsType -> {
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
        fun newPDUSessionModificationRequest(iei: UByte): PDUSessionModificationRequest {
            return PDUSessionModificationRequest()
        }

        const val PDUSessionModificationRequestCapability5GSMType: UByte = 0x28u
        const val PDUSessionModificationRequestCause5GSMType: UByte = 0x59u
        const val PDUSessionModificationRequestMaximumNumberOfSupportedPacketFiltersType: UByte = 0x55u
        const val PDUSessionModificationRequestAlwaysonPDUSessionRequestedType: UByte = 0x0Bu
        const val PDUSessionModificationRequestIntegrityProtectionMaximumDataRateType: UByte = 0x13u
        const val PDUSessionModificationRequestRequestedQosRulesType: UByte = 0x7Au
        const val PDUSessionModificationRequestRequestedQosFlowDescriptionsType: UByte = 0x79u
        const val PDUSessionModificationRequestMappedEPSBearerContextsType: UByte = 0x7Fu
        const val PDUSessionModificationRequestExtendedProtocolConfigurationOptionsType: UByte = 0x7Bu
    }
}