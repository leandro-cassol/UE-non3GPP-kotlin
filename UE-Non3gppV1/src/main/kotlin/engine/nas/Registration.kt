package engine.nas

import engine.util.hexStringToByteArray
import engine.util.toByteArray
import free5gc.nas.GmmMessage
import free5gc.nas.GsmMessage
import free5gc.nas.Message
import free5gc.nas.SecurityHeader
import free5gc.nas.nasConvert.ProtocolConfigurationOptions
import free5gc.nas.nasMessage.*
import free5gc.nas.nasType.*
import free5gc.openapi.models.Snssai
import java.nio.ByteBuffer
import java.util.*


fun getRegistrationRequest(
    registrationType: UByte,
    mobileIdentity: MobileIdentity5GS,
    requestedNSSAI: RequestedNSSAI?,
    ueSecurityCapability: UESecurityCapability?,
    capability5GMM: Capability5GMM?,
    nasMessageContainer: ByteArray?,
    uplinkDataStatus: UplinkDataStatus?
): ByteArray {
    val m = Message.newMessage()
    m.gmmMessage = GmmMessage.newGmmMessage()
    m.gmmMessage!!.gmmHeader.setMessageType(Message.MsgTypeRegistrationRequest)

    val registrationRequest = RegistrationRequest.newRegistrationRequest(0u)
    registrationRequest.extendedProtocolDiscriminator.setExtendedProtocolDiscriminator(Epd5GSMobilityManagementMessage)
    registrationRequest.spareHalfOctetAndSecurityHeaderType.setSecurityHeaderType(SecurityHeader.SecurityHeaderTypePlainNas)
    registrationRequest.spareHalfOctetAndSecurityHeaderType.setSpareHalfOctet(0x00u)
    registrationRequest.registrationRequestMessageIdentity.setMessageType(Message.MsgTypeRegistrationRequest)
    registrationRequest.ngksiAndRegistrationType5GS.setTSC(CommInfoIE.TypeOfSecurityContextFlagNative)
    registrationRequest.ngksiAndRegistrationType5GS.setNasKeySetIdentifiler(0x7u)
    registrationRequest.ngksiAndRegistrationType5GS.setFOR(1u)
    registrationRequest.ngksiAndRegistrationType5GS.setRegistrationType5GS(registrationType)
    registrationRequest.mobileIdentity5GS = mobileIdentity

    registrationRequest.ueSecurityCapability = ueSecurityCapability
    registrationRequest.capability5GMM = capability5GMM
    registrationRequest.requestedNSSAI = requestedNSSAI
    registrationRequest.uplinkDataStatus = uplinkDataStatus

    if (nasMessageContainer != null) {
        registrationRequest.nasMessageContainer = NASMessageContainer.newNASMessageContainer(RegistrationRequest.RegistrationRequestNASMessageContainerType)
        registrationRequest.nasMessageContainer!!.setLen(nasMessageContainer.size.toUShort())
        registrationRequest.nasMessageContainer!!.setNASMessageContainerContents(nasMessageContainer.toUByteArray())
    }

    m.gmmMessage!!.registrationRequest = registrationRequest
    val data = ByteBuffer.allocate(1024)
    m.gmmMessageEncode(data)

    return data.flip().toByteArray()
}


fun getAuthenticationResponse(authenticationResponseParam: ByteArray, eapMsg: String?): ByteArray {
    val m = Message.newMessage()
    m.gmmMessage = GmmMessage.newGmmMessage()
    m.gmmMessage!!.gmmHeader.setMessageType(Message.MsgTypeAuthenticationResponse)

    val authenticationResponse = AuthenticationResponse.NewAuthenticationResponse(0u)
    authenticationResponse.extendedProtocolDiscriminator.setExtendedProtocolDiscriminator(Epd5GSMobilityManagementMessage)
    authenticationResponse.spareHalfOctetAndSecurityHeaderType.setSecurityHeaderType(SecurityHeader.SecurityHeaderTypePlainNas)
    authenticationResponse.spareHalfOctetAndSecurityHeaderType.setSpareHalfOctet(0u)
    authenticationResponse.authenticationResponseMessageIdentity.setMessageType(Message.MsgTypeAuthenticationResponse)

    if (authenticationResponseParam.isNotEmpty()) {
        authenticationResponse.authenticationResponseParameter =
            AuthenticationResponseParameter.newAuthenticationResponseParameter(AuthenticationResponse.AuthenticationResponseAuthenticationResponseParameterType)

        authenticationResponse.authenticationResponseParameter!!.setLen(authenticationResponseParam.size.toUByte())
        authenticationResponse.authenticationResponseParameter!!.octet = authenticationResponseParam.copyOfRange(0, 16).toUByteArray()
    } else if (!eapMsg.isNullOrEmpty()) {
        val rawEapMsg = Base64.getDecoder().decode(eapMsg)
        authenticationResponse.eapMessage = EAPMessage.newEAPMessage(AuthenticationResponse.AuthenticationResponseEAPMessageType)
        authenticationResponse.eapMessage!!.setLen(rawEapMsg.size.toUShort())
        authenticationResponse.eapMessage!!.setEAPMessage(rawEapMsg.toUByteArray())
    }

    m.gmmMessage!!.authenticationResponse = authenticationResponse
    val data = ByteBuffer.allocate(1024)
    m.gmmMessageEncode(data)

    return data.flip().toByteArray()
}


// TS 24.501 8.2.26.
fun getSecurityModeComplete(nasMessageContainer: ByteArray?): ByteArray {
    val m = Message.newMessage()
    m.gmmMessage = GmmMessage.newGmmMessage()
    m.gmmMessage!!.gmmHeader.setMessageType(Message.MsgTypeSecurityModeComplete)

    val securityModeComplete = SecurityModeComplete.NewSecurityModeComplete(0u)
    securityModeComplete.extendedProtocolDiscriminator.setExtendedProtocolDiscriminator(Epd5GSMobilityManagementMessage)
    securityModeComplete.spareHalfOctetAndSecurityHeaderType.setSecurityHeaderType(SecurityHeader.SecurityHeaderTypePlainNas)
    securityModeComplete.spareHalfOctetAndSecurityHeaderType.setSpareHalfOctet(0u)
    securityModeComplete.securityModeCompleteMessageIdentity.setMessageType(Message.MsgTypeSecurityModeComplete)
    securityModeComplete.imeisv = IMEISV.newIMEISV(SecurityModeComplete.SecurityModeCompleteIMEISVType)
    securityModeComplete.imeisv!!.setLen(9u)
    securityModeComplete.imeisv!!.setOddEvenIdic(0u)
    securityModeComplete.imeisv!!.setTypeOfIdentity(CommInfoIE.MobileIdentity5GSTypeImeisv)
    securityModeComplete.imeisv!!.setIdentityDigit1(1u)
    securityModeComplete.imeisv!!.setIdentityDigitP_1(1u)
    securityModeComplete.imeisv!!.setIdentityDigitP(1u)

    if (nasMessageContainer != null) {
        securityModeComplete.nasMessageContainer = NASMessageContainer.newNASMessageContainer(SecurityModeComplete.SecurityModeCompleteNASMessageContainerType)
        securityModeComplete.nasMessageContainer!!.setLen(nasMessageContainer.size.toUShort())
        securityModeComplete.nasMessageContainer!!.setNASMessageContainerContents(nasMessageContainer.toUByteArray())
    }

    m.gmmMessage!!.securityModeComplete = securityModeComplete
    val data = ByteBuffer.allocate(1024)
    m.gmmMessageEncode(data)

    return data.flip().toByteArray()
}


fun getRegistrationComplete(sorTransparentContainer: ByteArray?): ByteArray {
    val m = Message.newMessage()
    m.gmmMessage = GmmMessage.newGmmMessage()
    m.gmmMessage!!.gmmHeader.setMessageType(Message.MsgTypeRegistrationComplete)

    val registrationComplete = RegistrationComplete.newRegistrationComplete(0u)
    registrationComplete.extendedProtocolDiscriminator.setExtendedProtocolDiscriminator(Epd5GSMobilityManagementMessage)
    registrationComplete.spareHalfOctetAndSecurityHeaderType.setSecurityHeaderType(SecurityHeader.SecurityHeaderTypePlainNas)
    registrationComplete.spareHalfOctetAndSecurityHeaderType.setSpareHalfOctet(0u)
    registrationComplete.registrationCompleteMessageIdentity.setMessageType(Message.MsgTypeRegistrationComplete)

    if (sorTransparentContainer != null) {
        registrationComplete.sorTransparentContainer = SORTransparentContainer.newSORTransparentContainer(RegistrationComplete.RegistrationCompleteSORTransparentContainerType)
        registrationComplete.sorTransparentContainer!!.setLen(sorTransparentContainer.size.toUShort())
        registrationComplete.sorTransparentContainer!!.setSORContent(sorTransparentContainer.toUByteArray())
    }

    m.gmmMessage!!.registrationComplete = registrationComplete
    val data = ByteBuffer.allocate(1024)
    m.gmmMessageEncode(data)

    return data.flip().toByteArray()
}


fun getUlNasTransportPduSessionEstablishmentRequest(pduSessionId: UByte, requestType: UByte, dnnString: String, snssai: Snssai?): ByteArray {
    val pduSessionEstablishmentRequest = getPduSessionEstablishmentRequest(pduSessionId)

    val m = Message.newMessage()
    m.gmmMessage = GmmMessage.newGmmMessage()
    m.gmmMessage!!.gmmHeader.setMessageType(Message.MsgTypeULNASTransport)

    val ulNasTransport = ULNASTransport.newULNASTransport(0u)
    ulNasTransport.spareHalfOctetAndSecurityHeaderType.setSecurityHeaderType(SecurityHeader.SecurityHeaderTypePlainNas)
    ulNasTransport.uLNASTRANSPORTMessageIdentity.setMessageType(Message.MsgTypeULNASTransport)
    ulNasTransport.extendedProtocolDiscriminator.setExtendedProtocolDiscriminator(Epd5GSMobilityManagementMessage)

    ulNasTransport.pduSessionID2Value = PduSessionID2Value()
    ulNasTransport.pduSessionID2Value!!.setIei(ULNASTransport.ULNASTransportPduSessionID2ValueType)
    ulNasTransport.pduSessionID2Value!!.setPduSessionID2Value(pduSessionId)

    ulNasTransport.requestType = RequestType()
    ulNasTransport.requestType!!.setIei(ULNASTransport.ULNASTransportRequestTypeType)
    ulNasTransport.requestType!!.setRequestTypeValue(requestType)
    if (dnnString.isNotEmpty()) {
        ulNasTransport.dnn = DNN()
        ulNasTransport.dnn!!.setIei(ULNASTransport.ULNASTransportDNNType)
        ulNasTransport.dnn!!.setDNN(dnnString)
    }
    if (snssai != null) {
        val sdTemp = ByteArray(3)
        val sd = hexStringToByteArray(snssai.sd!!)
        sd.copyInto(sdTemp)

        ulNasTransport.sNSSAI = SNSSAI.newSNSSAI(ULNASTransport.ULNASTransportSNSSAIType)
        ulNasTransport.sNSSAI!!.setLen(4u)
        ulNasTransport.sNSSAI!!.setSST(snssai.sst.toUByte())
        ulNasTransport.sNSSAI!!.setSD(sdTemp.toUByteArray())
    }

    ulNasTransport.spareHalfOctetAndPayloadContainerType.setPayloadContainerType(CommInfoIE.PayloadContainerTypeN1SMInfo)
    ulNasTransport.payloadContainer.setLen(pduSessionEstablishmentRequest.size.toUShort())
    ulNasTransport.payloadContainer.setPayloadContainerContents(pduSessionEstablishmentRequest.toUByteArray())

    m.gmmMessage!!.ulNASTransport = ulNasTransport
    val data = ByteBuffer.allocate(1024)
    m.gmmMessageEncode(data)

    return data.flip().toByteArray()
}


fun getPduSessionEstablishmentRequest(pduSessionId: UByte): ByteArray {
    val m = Message.newMessage()
    m.gsmMessage = GsmMessage.newGsmMessage()
    m.gsmMessage!!.gsmHeader.setMessageType(Message.MsgTypePDUSessionEstablishmentRequest)

    val pduSessionEstablishmentRequest = PDUSessionEstablishmentRequest.NewPDUSessionEstablishmentRequest(0u)
    pduSessionEstablishmentRequest.extendedProtocolDiscriminator.setExtendedProtocolDiscriminator(Epd5GSSessionManagementMessage)
    pduSessionEstablishmentRequest.pDUSESSIONESTABLISHMENTREQUESTMessageIdentity.setMessageType(Message.MsgTypePDUSessionEstablishmentRequest)
    pduSessionEstablishmentRequest.pduSessionID.setPDUSessionID(pduSessionId)
    pduSessionEstablishmentRequest.pti.setPTI((0x00).toUByte())
    pduSessionEstablishmentRequest.integrityProtectionMaximumDataRate.setMaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink((0xff).toUByte())
    pduSessionEstablishmentRequest.integrityProtectionMaximumDataRate.setMaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink((0xff).toUByte())

    pduSessionEstablishmentRequest.pDUSessionType = PDUSessionType.newPDUSessionType(PDUSessionEstablishmentRequest.PDUSessionEstablishmentRequestPDUSessionTypeType)
    pduSessionEstablishmentRequest.pDUSessionType!!.setPDUSessionTypeValue((0x01).toUByte())

    pduSessionEstablishmentRequest.extendedProtocolConfigurationOptions =
        ExtendedProtocolConfigurationOptions.newExtendedProtocolConfigurationOptions(
            PDUSessionEstablishmentRequest.PDUSessionEstablishmentRequestExtendedProtocolConfigurationOptionsType)

    val protocolConfigurationOptions = ProtocolConfigurationOptions.newProtocolConfigurationOptions()
    protocolConfigurationOptions.addIPAddressAllocationViaNASSignallingUL()
    protocolConfigurationOptions.addDNSServerIPv4AddressRequest()
    protocolConfigurationOptions.addDNSServerIPv6AddressRequest()
    val pcoContents = protocolConfigurationOptions.marshal()
    val pcoContentsLength = pcoContents.size

    pduSessionEstablishmentRequest.extendedProtocolConfigurationOptions!!.setLen(pcoContentsLength.toUShort())
    pduSessionEstablishmentRequest.extendedProtocolConfigurationOptions!!.setExtendedProtocolConfigurationOptionsContents(pcoContents.toUByteArray())

    m.gsmMessage!!.pduSessionEstablishmentRequest = pduSessionEstablishmentRequest
    val data = ByteBuffer.allocate(1024)
    m.gsmMessageEncode(data)

    return data.flip().toByteArray()
}