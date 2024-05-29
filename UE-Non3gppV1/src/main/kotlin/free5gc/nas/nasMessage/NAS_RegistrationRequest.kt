package free5gc.nas.nasMessage

import free5gc.nas.nasType.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RegistrationRequest {
    var extendedProtocolDiscriminator: ExtendedProtocolDiscriminator = ExtendedProtocolDiscriminator()
    var spareHalfOctetAndSecurityHeaderType: SpareHalfOctetAndSecurityHeaderType = SpareHalfOctetAndSecurityHeaderType()
    var registrationRequestMessageIdentity: RegistrationRequestMessageIdentity = RegistrationRequestMessageIdentity()
    var ngksiAndRegistrationType5GS: NgksiAndRegistrationType5GS = NgksiAndRegistrationType5GS()
    var mobileIdentity5GS: MobileIdentity5GS = MobileIdentity5GS()
    var noncurrentNativeNASKeySetIdentifier: NoncurrentNativeNASKeySetIdentifier? = null
    var capability5GMM: Capability5GMM? = null
    var ueSecurityCapability: UESecurityCapability? = null
    var requestedNSSAI: RequestedNSSAI? = null
    var lastVisitedRegisteredTAI: LastVisitedRegisteredTAI? = null
    var s1UENetworkCapability: S1UENetworkCapability? = null
    var uplinkDataStatus: UplinkDataStatus? = null
    var pduSessionStatus: PDUSessionStatus? = null
    var micoIndication: MICOIndication? = null
    var ueStatus: UEStatus? = null
    var additionalGUTI: AdditionalGUTI? = null
    var allowedPDUSessionStatus: AllowedPDUSessionStatus? = null
    var uesUsageSetting: UesUsageSetting? = null
    var requestedDRXParameters: RequestedDRXParameters? = null
    var epsNASMessageContainer: EPSNASMessageContainer? = null
    var ladnIndication: LADNIndication? = null
    var payloadContainer: PayloadContainer? = null
    var networkSlicingIndication: NetworkSlicingIndication? = null
    var updateType5GS: UpdateType5GS? = null
    var nasMessageContainer: NASMessageContainer? = null

    companion object {
        const val RegistrationRequestNoncurrentNativeNASKeySetIdentifierType: UByte = 0x0Cu
        const val RegistrationRequestCapability5GMMType: UByte = 0x10u
        const val RegistrationRequestUESecurityCapabilityType: UByte = 0x2Eu
        const val RegistrationRequestRequestedNSSAIType: UByte = 0x2Fu
        const val RegistrationRequestLastVisitedRegisteredTAIType: UByte = 0x52u
        const val RegistrationRequestS1UENetworkCapabilityType: UByte = 0x17u
        const val RegistrationRequestUplinkDataStatusType: UByte = 0x40u
        const val RegistrationRequestPDUSessionStatusType: UByte = 0x50u
        const val RegistrationRequestMICOIndicationType: UByte = 0x0Bu
        const val RegistrationRequestUEStatusType: UByte = 0x2Bu
        const val RegistrationRequestAdditionalGUTIType: UByte = 0x77u
        const val RegistrationRequestAllowedPDUSessionStatusType: UByte = 0x25u
        const val RegistrationRequestUesUsageSettingType: UByte = 0x18u
        const val RegistrationRequestRequestedDRXParametersType: UByte = 0x51u
        const val RegistrationRequestEPSNASMessageContainerType: UByte = 0x70u
        const val RegistrationRequestLADNIndicationType: UByte = 0x74u
        const val RegistrationRequestPayloadContainerType: UByte = 0x7Bu
        const val RegistrationRequestNetworkSlicingIndicationType: UByte = 0x09u
        const val RegistrationRequestUpdateType5GSType: UByte = 0x53u
        const val RegistrationRequestNASMessageContainerType: UByte = 0x71u

        fun newRegistrationRequest(iei: UByte): RegistrationRequest {
            return RegistrationRequest()
        }
    }

    fun encodeRegistrationRequest(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.put(extendedProtocolDiscriminator.octet.toByte())
        buffer.put(spareHalfOctetAndSecurityHeaderType.octet.toByte())
        buffer.put(registrationRequestMessageIdentity.octet.toByte())
        buffer.put(ngksiAndRegistrationType5GS.octet.toByte())

        buffer.putShort(mobileIdentity5GS.len.toShort())
        buffer.put(mobileIdentity5GS.buffer.toByteArray())

        noncurrentNativeNASKeySetIdentifier?.let {
            buffer.put(it.octet.toByte())
        }
        capability5GMM?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        ueSecurityCapability?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        requestedNSSAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        lastVisitedRegisteredTAI?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.octet.toByteArray())
        }
        s1UENetworkCapability?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        uplinkDataStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        pduSessionStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        micoIndication?.let {
            buffer.put(it.octet.toByte())
        }
        ueStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        additionalGUTI?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.octet.toByteArray(), 0, it.getLen().toInt())
        }
        allowedPDUSessionStatus?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        uesUsageSetting?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        requestedDRXParameters?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        epsNASMessageContainer?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        ladnIndication?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        payloadContainer?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
        networkSlicingIndication?.let {
            buffer.put(it.octet.toByte())
        }
        updateType5GS?.let {
            buffer.put(it.getIei().toByte())
            buffer.put(it.getLen().toByte())
            buffer.put(it.octet.toByte())
        }
        nasMessageContainer?.let {
            buffer.put(it.getIei().toByte())
            buffer.putShort(it.getLen().toShort())
            buffer.put(it.buffer.toByteArray(), 0, it.getLen().toInt())
        }
    }

    fun decodeRegistrationRequest(byteArray: ByteArray) {
        val buffer = ByteBuffer.wrap(byteArray)
        buffer.order(ByteOrder.BIG_ENDIAN)

        extendedProtocolDiscriminator.octet = buffer.get().toUByte()
        spareHalfOctetAndSecurityHeaderType.octet = buffer.get().toUByte()
        registrationRequestMessageIdentity.octet = buffer.get().toUByte()
        ngksiAndRegistrationType5GS.octet = buffer.get().toUByte()

        mobileIdentity5GS.len = buffer.short.toUShort()
        mobileIdentity5GS.setLen(mobileIdentity5GS.getLen())
        buffer.get(mobileIdentity5GS.buffer.toByteArray())

        while (buffer.remaining() > 0) {
            val ieiN = buffer.get().toInt() and 0xFF
            val tmpIeiN: Int
            if (ieiN >= 0x80) {
                tmpIeiN = (ieiN and 0xF0) shr 4
            } else {
                tmpIeiN = ieiN
            }

            when (tmpIeiN.toUByte()) {
                RegistrationRequestNoncurrentNativeNASKeySetIdentifierType -> {
                    noncurrentNativeNASKeySetIdentifier = NoncurrentNativeNASKeySetIdentifier.newNoncurrentNativeNASKeySetIdentifier(ieiN.toUByte())
                    noncurrentNativeNASKeySetIdentifier!!.octet = buffer.get().toUByte()
                }

                RegistrationRequestCapability5GMMType -> {
                    capability5GMM = Capability5GMM.newCapability5GMM(ieiN.toUByte())

                    val len = capability5GMM!!.octet.size
                    capability5GMM!!.setLen(len.toUByte())

                    val octets = ByteArray(len)
                    buffer.get(octets)
                    capability5GMM!!.octet = octets.toUByteArray()
                }

                RegistrationRequestUESecurityCapabilityType -> {
                    ueSecurityCapability = UESecurityCapability.newUESecurityCapability(ieiN.toUByte())
                    ueSecurityCapability!!.setLen(buffer.get().toUByte())

                    val uscBuffer = ByteArray(ueSecurityCapability!!.getLen().toInt())
                    buffer.get(uscBuffer)
                    ueSecurityCapability!!.buffer = uscBuffer.toUByteArray()
                }

                RegistrationRequestRequestedNSSAIType -> {
                    requestedNSSAI = RequestedNSSAI.newRequestedNSSAI(ieiN.toUByte())
                    requestedNSSAI!!.setLen(buffer.get().toUByte())

                    val rnBuffer = ByteArray(requestedNSSAI!!.getLen().toInt())
                    buffer.get(rnBuffer)
                    requestedNSSAI!!.buffer = rnBuffer.toUByteArray()
                }

                RegistrationRequestLastVisitedRegisteredTAIType -> {
                    lastVisitedRegisteredTAI = LastVisitedRegisteredTAI.newLastVisitedRegisteredTAI(ieiN.toUByte())

                    val len = lastVisitedRegisteredTAI!!.octet.size
                    val octets = ByteArray(len)
                    buffer.get(octets)
                    lastVisitedRegisteredTAI!!.octet = octets.toUByteArray()
                }

                RegistrationRequestS1UENetworkCapabilityType -> {
                    s1UENetworkCapability = S1UENetworkCapability.newS1UENetworkCapability(ieiN.toUByte())
                    s1UENetworkCapability!!.setLen(buffer.get().toUByte())

                    val s1ncBuffer = ByteArray(s1UENetworkCapability!!.getLen().toInt())
                    buffer.get(s1ncBuffer)
                    s1UENetworkCapability!!.buffer = s1ncBuffer.toUByteArray()
                }

                RegistrationRequestUplinkDataStatusType -> {
                    uplinkDataStatus = UplinkDataStatus.newUplinkDataStatus(ieiN.toUByte())
                    uplinkDataStatus!!.setLen(buffer.get().toUByte())

                    val udBuffer = ByteArray(uplinkDataStatus!!.getLen().toInt())
                    buffer.get(udBuffer)
                    uplinkDataStatus!!.buffer = udBuffer.toUByteArray()
                }

                RegistrationRequestPDUSessionStatusType -> {
                    pduSessionStatus = PDUSessionStatus.newPDUSessionStatus(ieiN.toUByte())
                    pduSessionStatus!!.setLen(buffer.get().toUByte())

                    val pduBuffer = ByteArray(pduSessionStatus!!.getLen().toInt())
                    buffer.get(pduBuffer)
                    pduSessionStatus!!.buffer = pduBuffer.toUByteArray()
                }

                RegistrationRequestMICOIndicationType -> {
                    micoIndication = MICOIndication.newMICOIndication(ieiN.toUByte())
                    micoIndication!!.octet = ieiN.toUByte()
                }

                RegistrationRequestUEStatusType -> {
                    ueStatus = UEStatus.newUEStatus(ieiN.toUByte())
                    ueStatus!!.setLen(buffer.get().toUByte())
                    ueStatus!!.octet = buffer.get().toUByte()
                }

                RegistrationRequestAdditionalGUTIType -> {
                    additionalGUTI = AdditionalGUTI.newAdditionalGUTI(ieiN.toUByte())

                    val len = additionalGUTI!!.octet.size
                    additionalGUTI!!.setLen(len.toUShort())

                    val octets = ByteArray(len)
                    buffer.get(octets)
                    additionalGUTI!!.octet = octets.toUByteArray()
                }

                RegistrationRequestAllowedPDUSessionStatusType -> {
                    allowedPDUSessionStatus = AllowedPDUSessionStatus.newAllowedPDUSessionStatus(ieiN.toUByte())
                    allowedPDUSessionStatus!!.setLen(buffer.get().toUByte())

                    val auxBuffer = ByteArray(allowedPDUSessionStatus!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    allowedPDUSessionStatus!!.buffer = auxBuffer.toUByteArray()
                }

                RegistrationRequestUesUsageSettingType -> {
                    uesUsageSetting = UesUsageSetting.newUesUsageSetting(ieiN.toUByte())
                    uesUsageSetting!!.setLen(buffer.get().toUByte())
                    uesUsageSetting!!.octet = buffer.get().toUByte()
                }

                RegistrationRequestRequestedDRXParametersType -> {
                    requestedDRXParameters = RequestedDRXParameters.newRequestedDRXParameters(ieiN.toUByte())
                    requestedDRXParameters!!.setLen(buffer.get().toUByte())
                    requestedDRXParameters!!.octet = buffer.get().toUByte()
                }

                RegistrationRequestEPSNASMessageContainerType -> {
                    epsNASMessageContainer = EPSNASMessageContainer.newEPSNASMessageContainer(ieiN.toUByte())
                    epsNASMessageContainer!!.setLen(buffer.short.toUShort())

                    val auxBuffer = ByteArray(epsNASMessageContainer!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    epsNASMessageContainer!!.buffer = auxBuffer.toUByteArray()
                }

                RegistrationRequestLADNIndicationType -> {
                    ladnIndication = LADNIndication.newLADNIndication(ieiN.toUByte())
                    ladnIndication!!.setLen(buffer.short.toUShort())

                    val auxBuffer = ByteArray(ladnIndication!!.getLen().toInt())
                    buffer.get(auxBuffer)
                    ladnIndication!!.buffer = auxBuffer.toUByteArray()
                }

                RegistrationRequestPayloadContainerType -> {
                    payloadContainer = PayloadContainer.newPayloadContainer(ieiN.toUByte())
                    payloadContainer!!.setLen(buffer.short.toUShort())

                    val plcBuffer = ByteArray(payloadContainer!!.getLen().toInt())
                    buffer.get(plcBuffer)
                    payloadContainer!!.buffer = plcBuffer.toUByteArray()
                }

                RegistrationRequestNetworkSlicingIndicationType -> {
                    networkSlicingIndication = NetworkSlicingIndication.newNetworkSlicingIndication(ieiN.toUByte())
                    networkSlicingIndication!!.octet = ieiN.toUByte()
                }

                RegistrationRequestUpdateType5GSType -> {
                    updateType5GS = UpdateType5GS.newUpdateType5GS(ieiN.toUByte())
                    updateType5GS!!.setLen(buffer.get().toUByte())
                    updateType5GS!!.octet = buffer.get().toUByte()
                }

                RegistrationRequestNASMessageContainerType -> {
                    nasMessageContainer = NASMessageContainer.newNASMessageContainer(ieiN.toUByte())
                    nasMessageContainer!!.setLen(buffer.short.toUShort())

                    val nasMCBuffer = ByteArray(nasMessageContainer!!.getLen().toInt())
                    buffer.get(nasMCBuffer)
                    nasMessageContainer!!.buffer = nasMCBuffer.toUByteArray()
                }
                else -> {
                }
            }
        }
    }
}