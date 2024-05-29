package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RegistrationAccept {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var registrationAcceptMessageIdentity: RegistrationAcceptMessageIdentity = RegistrationAcceptMessageIdentity()
    var registrationResult5GS: RegistrationResult5GS = RegistrationResult5GS()
    var guti5G: GUTI5G? = null
    var equivalentPlmns: EquivalentPlmns? = null
    var taiList: TAIList? = null
    var allowedNSSAI: AllowedNSSAI? = null
    var rejectedNSSAI: RejectedNSSAI? = null
    var configuredNSSAI: ConfiguredNSSAI? = null
    var networkFeatureSupport5GS: NetworkFeatureSupport5GS? = null
    var pduSessionStatus: PDUSessionStatus? = null
    var pduSessionReactivationResult: PDUSessionReactivationResult? = null
    var pduSessionReactivationResultErrorCause: PDUSessionReactivationResultErrorCause? = null
    var ladnInformation: LADNInformation? = null
    var micoIndication: MICOIndication? = null
    var networkSlicingIndication: NetworkSlicingIndication? = null
    var serviceAreaList: ServiceAreaList? = null
    var t3512Value: T3512Value? = null
    var non3GppDeregistrationTimerValue: Non3GppDeregistrationTimerValue? = null
    var t3502Value: T3502Value? = null
    var emergencyNumberList: EmergencyNumberList? = null
    var extendedEmergencyNumberList: ExtendedEmergencyNumberList? = null
    var sorTransparentContainer: SORTransparentContainer? = null
    var eapMessage: EAPMessage? = null
    var nssaiInclusionMode: NSSAIInclusionMode? = null
    var operatordefinedAccessCategoryDefinitions: OperatordefinedAccessCategoryDefinitions? = null
    var negotiatedDRXParameters: NegotiatedDRXParameters? = null

    fun encodeRegistrationAccept(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)

        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(registrationAcceptMessageIdentity.octet.toByte())

        buffer.put(registrationResult5GS.getLen().toByte())
        buffer.put(registrationResult5GS.octet.toByte())

        guti5G?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        equivalentPlmns?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        taiList?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        allowedNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        rejectedNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        configuredNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        networkFeatureSupport5GS?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        pduSessionStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        pduSessionReactivationResult?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        pduSessionReactivationResultErrorCause?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        ladnInformation?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        micoIndication?.let {
            buffer.put(it.octet.toByte())
        }
        networkSlicingIndication?.let {
            buffer.put(it.octet.toByte())
        }
        serviceAreaList?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        t3512Value?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        non3GppDeregistrationTimerValue?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        t3502Value?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        emergencyNumberList?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        extendedEmergencyNumberList?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        sorTransparentContainer?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        eapMessage?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray())
        }
        nssaiInclusionMode?.let {
            buffer.put(it.octet.toByte())
        }
        operatordefinedAccessCategoryDefinitions?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        negotiatedDRXParameters?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
    }

    fun decodeRegistrationAccept(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        registrationAcceptMessageIdentity.octet = buffer.get().toUByte()

        registrationResult5GS.setLen(buffer.get().toUByte())
        registrationResult5GS.octet = buffer.get().toUByte()

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                RegistrationAcceptGUTI5GType -> {
                    guti5G = GUTI5G.newGUTI5G(ieiN.toUByte())
                    guti5G!!.setLen(buffer.short.toUShort())

                    val auxByteArray = ByteArray(guti5G!!.getLen().toInt())
                    buffer.get(auxByteArray)
                    guti5G!!.octet = auxByteArray.toUByteArray()

                }

                RegistrationAcceptEquivalentPlmnsType -> {
                    equivalentPlmns = EquivalentPlmns.newEquivalentPlmns(ieiN.toUByte())
                    val len = equivalentPlmns!!.octet.size
                    equivalentPlmns!!.setLen(len.toUByte())

                    val auxByteArray = ByteArray(equivalentPlmns!!.getLen().toInt())
                    buffer.get(auxByteArray)
                    equivalentPlmns!!.octet = auxByteArray.toUByteArray()

                }

                RegistrationAcceptTAIListType -> {
                    taiList = TAIList.newTAIList(ieiN.toUByte())
                    taiList!!.setLen(buffer.get().toUByte())

                    val taiBuffer = ByteArray(taiList!!.getLen().toInt())
                    buffer.get(taiBuffer)
                    taiList!!.buffer = taiBuffer.toUByteArray()
                }

                RegistrationAcceptAllowedNSSAIType -> {
                    allowedNSSAI = AllowedNSSAI.newAllowedNSSAI(ieiN.toUByte())
                    allowedNSSAI!!.setLen(buffer.get().toUByte())

                    val alloBuffer = ByteArray(allowedNSSAI!!.getLen().toInt())
                    buffer.get(alloBuffer)
                    allowedNSSAI!!.buffer = alloBuffer.toUByteArray()
                }

                RegistrationAcceptRejectedNSSAIType -> {
                    rejectedNSSAI = RejectedNSSAI.newRejectedNSSAI(ieiN.toUByte())
                    rejectedNSSAI!!.setLen(buffer.get().toUByte())

                    val rejBuffer = ByteArray(rejectedNSSAI!!.getLen().toInt())
                    buffer.get(rejBuffer)
                    rejectedNSSAI!!.buffer = rejBuffer.toUByteArray()
                }

                RegistrationAcceptConfiguredNSSAIType -> {
                    configuredNSSAI = ConfiguredNSSAI.newConfiguredNSSAI(ieiN.toUByte())
                    configuredNSSAI!!.setLen(buffer.get().toUByte())

                    val confBuffer = ByteArray(configuredNSSAI!!.getLen().toInt())
                    buffer.get(confBuffer)
                    configuredNSSAI!!.buffer = confBuffer.toUByteArray()
                }

                RegistrationAcceptNetworkFeatureSupport5GSType -> {
                    networkFeatureSupport5GS = NetworkFeatureSupport5GS.newNetworkFeatureSupport5GS(ieiN.toUByte())
                    val len = networkFeatureSupport5GS!!.octet.size
                    networkFeatureSupport5GS!!.setLen(len.toUByte())

                    val auxByteArray = ByteArray(networkFeatureSupport5GS!!.getLen().toInt())
                    buffer.get(auxByteArray)
                    networkFeatureSupport5GS!!.octet = auxByteArray.toUByteArray()

                }

                RegistrationAcceptPDUSessionStatusType -> {
                    pduSessionStatus = PDUSessionStatus.newPDUSessionStatus(ieiN.toUByte())
                    pduSessionStatus!!.setLen(buffer.get().toUByte())

                    val pduBuffer = ByteArray(pduSessionStatus!!.getLen().toInt())
                    buffer.get(pduBuffer)
                    pduSessionStatus!!.buffer = pduBuffer.toUByteArray()
                }

                RegistrationAcceptPDUSessionReactivationResultType -> {
                    pduSessionReactivationResult = PDUSessionReactivationResult.newPDUSessionReactivationResult(ieiN.toUByte())
                    pduSessionReactivationResult!!.setLen(buffer.get().toUByte())

                    val psrBuffer = ByteArray(pduSessionReactivationResult!!.getLen().toInt())
                    buffer.get(psrBuffer)
                    pduSessionReactivationResult!!.buffer = psrBuffer.toUByteArray()
                }

                RegistrationAcceptPDUSessionReactivationResultErrorCauseType -> {
                    pduSessionReactivationResultErrorCause = PDUSessionReactivationResultErrorCause.newPDUSessionReactivationResultErrorCause(ieiN.toUByte())
                    pduSessionReactivationResultErrorCause!!.setLen(buffer.short.toUShort())

                    val psrErrorBuffer = ByteArray(pduSessionReactivationResultErrorCause!!.getLen().toInt())
                    buffer.get(psrErrorBuffer)
                    pduSessionReactivationResultErrorCause!!.buffer = psrErrorBuffer.toUByteArray()
                }

                RegistrationAcceptLADNInformationType -> {
                    ladnInformation = LADNInformation.newLADNInformation(ieiN.toUByte())
                    ladnInformation!!.setLen(buffer.short.toUShort())

                    val ladnBuffer = ByteArray(ladnInformation!!.getLen().toInt())
                    buffer.get(ladnBuffer)
                    ladnInformation!!.buffer = ladnBuffer.toUByteArray()
                }

                RegistrationAcceptMICOIndicationType -> {
                    micoIndication = MICOIndication.newMICOIndication(ieiN.toUByte())
                    micoIndication!!.octet = ieiN.toUByte()
                }

                RegistrationAcceptNetworkSlicingIndicationType -> {
                    networkSlicingIndication = NetworkSlicingIndication.newNetworkSlicingIndication(ieiN.toUByte())
                    networkSlicingIndication!!.octet = ieiN.toUByte()
                }

                RegistrationAcceptServiceAreaListType -> {
                    serviceAreaList = ServiceAreaList.newServiceAreaList(ieiN.toUByte())
                    serviceAreaList!!.setLen(buffer.get().toUByte())

                    val saBuffer = ByteArray(serviceAreaList!!.getLen().toInt())
                    buffer.get(saBuffer)
                    serviceAreaList!!.buffer = saBuffer.toUByteArray()
                }

                RegistrationAcceptT3512ValueType -> {
                    t3512Value = T3512Value.newT3512Value(ieiN.toUByte())
                    t3512Value!!.setLen(buffer.get().toUByte())
                    t3512Value!!.octet = buffer.get().toUByte()
                }

                RegistrationAcceptNon3GppDeregistrationTimerValueType -> {
                    non3GppDeregistrationTimerValue = Non3GppDeregistrationTimerValue.newNon3GppDeregistrationTimerValue(ieiN.toUByte())
                    non3GppDeregistrationTimerValue!!.setLen(buffer.get().toUByte())
                    non3GppDeregistrationTimerValue!!.octet = buffer.get().toUByte()
                }

                RegistrationAcceptT3502ValueType -> {
                    t3502Value = T3502Value.newT3502Value(ieiN.toUByte())
                    t3502Value!!.setLen(buffer.get().toUByte())
                    t3502Value!!.octet = buffer.get().toUByte()
                }

                RegistrationAcceptEmergencyNumberListType -> {
                    emergencyNumberList = EmergencyNumberList.newEmergencyNumberList(ieiN.toUByte())
                    emergencyNumberList!!.setLen(buffer.get().toUByte())

                    val enBuffer = ByteArray(emergencyNumberList!!.getLen().toInt())
                    buffer.get(enBuffer)
                    emergencyNumberList!!.buffer = enBuffer.toUByteArray()
                }

                RegistrationAcceptExtendedEmergencyNumberListType -> {
                    extendedEmergencyNumberList = ExtendedEmergencyNumberList.newExtendedEmergencyNumberList(ieiN.toUByte())
                    extendedEmergencyNumberList!!.setLen(buffer.short.toUShort())

                    val eenBuffer = ByteArray(extendedEmergencyNumberList!!.getLen().toInt())
                    buffer.get(eenBuffer)
                    extendedEmergencyNumberList!!.buffer = eenBuffer.toUByteArray()
                }

                RegistrationAcceptSORTransparentContainerType -> {
                    sorTransparentContainer = SORTransparentContainer.newSORTransparentContainer(ieiN.toUByte())
                    sorTransparentContainer!!.setLen(buffer.short.toUShort())

                    val stBuffer = ByteArray(sorTransparentContainer!!.getLen().toInt())
                    buffer.get(stBuffer)
                    sorTransparentContainer!!.buffer = stBuffer.toUByteArray()
                }

                RegistrationAcceptEAPMessageType -> {
                    eapMessage = EAPMessage.newEAPMessage(ieiN.toUByte())
                    eapMessage!!.setLen(buffer.short.toUShort())

                    val eapBuffer = ByteArray(eapMessage!!.getLen().toInt())
                    buffer.get(eapBuffer)
                    eapMessage!!.buffer = eapBuffer.toUByteArray()
                }

                RegistrationAcceptNSSAIInclusionModeType -> {
                    nssaiInclusionMode = NSSAIInclusionMode.newNSSAIInclusionMode(ieiN.toUByte())
                    nssaiInclusionMode!!.octet = ieiN.toUByte()
                }

                RegistrationAcceptOperatordefinedAccessCategoryDefinitionsType -> {
                    operatordefinedAccessCategoryDefinitions = OperatordefinedAccessCategoryDefinitions.newOperatordefinedAccessCategoryDefinitions(ieiN.toUByte())
                    operatordefinedAccessCategoryDefinitions!!.setLen(buffer.short.toUShort())

                    val operBuffer = ByteArray(operatordefinedAccessCategoryDefinitions!!.getLen().toInt())
                    buffer.get(operBuffer)
                    operatordefinedAccessCategoryDefinitions!!.buffer = operBuffer.toUByteArray()
                }

                RegistrationAcceptNegotiatedDRXParametersType -> {
                    negotiatedDRXParameters = NegotiatedDRXParameters.newNegotiatedDRXParameters(ieiN.toUByte())
                    negotiatedDRXParameters!!.setLen(buffer.get().toUByte())
                    negotiatedDRXParameters!!.octet = buffer.get().toUByte()
                }

                else -> {
                }
            }
        }
    }

    companion object {
        fun newRegistrationAccept(iei: UByte): RegistrationAccept {
            return RegistrationAccept()
        }

        const val RegistrationAcceptGUTI5GType: UByte = 0x77u
        const val RegistrationAcceptEquivalentPlmnsType: UByte = 0x4Au
        const val RegistrationAcceptTAIListType: UByte = 0x54u
        const val RegistrationAcceptAllowedNSSAIType: UByte = 0x15u
        const val RegistrationAcceptRejectedNSSAIType: UByte = 0x11u
        const val RegistrationAcceptConfiguredNSSAIType: UByte = 0x31u
        const val RegistrationAcceptNetworkFeatureSupport5GSType: UByte = 0x21u
        const val RegistrationAcceptPDUSessionStatusType: UByte = 0x50u
        const val RegistrationAcceptPDUSessionReactivationResultType: UByte = 0x26u
        const val RegistrationAcceptPDUSessionReactivationResultErrorCauseType: UByte = 0x72u
        const val RegistrationAcceptLADNInformationType: UByte = 0x79u
        const val RegistrationAcceptMICOIndicationType: UByte = 0x0Bu
        const val RegistrationAcceptNetworkSlicingIndicationType: UByte = 0x09u
        const val RegistrationAcceptServiceAreaListType: UByte = 0x27u
        const val RegistrationAcceptT3512ValueType: UByte = 0x5Eu
        const val RegistrationAcceptNon3GppDeregistrationTimerValueType: UByte = 0x5Du
        const val RegistrationAcceptT3502ValueType: UByte = 0x16u
        const val RegistrationAcceptEmergencyNumberListType: UByte = 0x34u
        const val RegistrationAcceptExtendedEmergencyNumberListType: UByte = 0x7Au
        const val RegistrationAcceptSORTransparentContainerType: UByte = 0x73u
        const val RegistrationAcceptEAPMessageType: UByte = 0x78u
        const val RegistrationAcceptNSSAIInclusionModeType: UByte = 0x0Au
        const val RegistrationAcceptOperatordefinedAccessCategoryDefinitionsType: UByte = 0x76u
        const val RegistrationAcceptNegotiatedDRXParametersType: UByte = 0x51u
    }
}