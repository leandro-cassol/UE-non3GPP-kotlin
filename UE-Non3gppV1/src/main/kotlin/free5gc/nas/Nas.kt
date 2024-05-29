package free5gc.nas

import engine.util.toByteArray
import free5gc.nas.nasMessage.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class SecurityHeader {
    var protocolDiscriminator: UByte = 0u
    var securityHeaderType: UByte = 0u
    var messageAuthenticationCode: UInt = 0u
    var sequenceNumber: UByte = 0u

    companion object {
        const val SecurityHeaderTypePlainNas: UByte = 0x00u
        const val SecurityHeaderTypeIntegrityProtected: UByte = 0x01u
        const val SecurityHeaderTypeIntegrityProtectedAndCiphered: UByte = 0x02u
        const val SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext: UByte = 0x03u
        const val SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext: UByte = 0x04u
    }
}

fun getEPD(byteArray: ByteArray): UByte {
    return byteArray[0].toUByte()
}

fun getSecurityHeaderType(byteArray: ByteArray): UByte {
    return byteArray[1].toUByte()
}





class GmmHeader {
    var octet: UByteArray = UByteArray(3)

    fun getMessageType(): UByte = octet[2]

    fun setMessageType(messageType: UByte) {
        octet[2] = messageType
    }

    fun getExtendedProtocolDiscriminator(): UByte = octet[0]

    fun setExtendedProtocolDiscriminator(epd: UByte) {
        octet[0] = epd
    }
}








class GmmMessage {
    var gmmHeader: GmmHeader = GmmHeader()
    var authenticationRequest: AuthenticationRequest? = null
    var authenticationResponse: AuthenticationResponse? = null
    var authenticationResult: AuthenticationResult? = null
    var authenticationFailure: AuthenticationFailure? = null
    var authenticationReject: AuthenticationReject? = null
    var registrationRequest: RegistrationRequest? = null
    var registrationAccept: RegistrationAccept? = null
    var registrationComplete: RegistrationComplete? = null
    var registrationReject: RegistrationReject? = null
    var ulNASTransport: ULNASTransport? = null
    var dlNASTransport: DLNASTransport? = null
    var deregistrationRequestUEOriginatingDeregistration: DeregistrationRequestUEOriginatingDeregistration? = null
    var deregistrationAcceptUEOriginatingDeregistration: DeregistrationAcceptUEOriginatingDeregistration? = null
    var deregistrationRequestUETerminatedDeregistration: DeregistrationRequestUETerminatedDeregistration? = null
    var deregistrationAcceptUETerminatedDeregistration: DeregistrationAcceptUETerminatedDeregistration? = null
    var serviceRequest: ServiceRequest? = null
    var serviceAccept: ServiceAccept? = null
    var serviceReject: ServiceReject? = null
    var configurationUpdateCommand: ConfigurationUpdateCommand? = null
    var configurationUpdateComplete: ConfigurationUpdateComplete? = null
    var identityRequest: IdentityRequest? = null
    var identityResponse: IdentityResponse? = null
    var notification: Notification? = null
    var notificationResponse: NotificationResponse? = null
    var securityModeCommand: SecurityModeCommand? = null
    var securityModeComplete: SecurityModeComplete? = null
    var securityModeReject: SecurityModeReject? = null
    var securityProtected5GSNASMessage: SecurityProtected5GSNASMessage? = null
    var status5GMM: Status5GMM? = null

    companion object {
        fun newGmmMessage(): GmmMessage {
            return GmmMessage()
        }
    }
}








class GsmHeader {
    var octet: UByteArray = UByteArray(4)

    fun getExtendedProtocolDiscriminator(): UByte = octet[0]

    fun setExtendedProtocolDiscriminator(epd: UByte) {
        octet[0] = epd
    }

    fun getMessageType(): UByte = octet[3]

    fun setMessageType(messageType: UByte) {
        octet[3] = messageType
    }
}






class GsmMessage {
    var gsmHeader: GsmHeader = GsmHeader()
    var pduSessionEstablishmentRequest: PDUSessionEstablishmentRequest? = null
    var pduSessionEstablishmentAccept: PDUSessionEstablishmentAccept? = null
    var pduSessionEstablishmentReject: PDUSessionEstablishmentReject? = null
    var pduSessionAuthenticationCommand: PDUSessionAuthenticationCommand? = null
    var pduSessionAuthenticationComplete: PDUSessionAuthenticationComplete? = null
    var pduSessionAuthenticationResult: PDUSessionAuthenticationResult? = null
    var pduSessionModificationRequest: PDUSessionModificationRequest? = null
    var pduSessionModificationReject: PDUSessionModificationReject? = null
    var pduSessionModificationCommand: PDUSessionModificationCommand? = null
    var pduSessionModificationComplete: PDUSessionModificationComplete? = null
    var pduSessionModificationCommandReject: PDUSessionModificationCommandReject? = null
    var pduSessionReleaseRequest: PDUSessionReleaseRequest? = null
    var pduSessionReleaseReject: PDUSessionReleaseReject? = null
    var pduSessionReleaseCommand: PDUSessionReleaseCommand? = null
    var pduSessionReleaseComplete: PDUSessionReleaseComplete? = null
    var status5GSM: Status5GSM? = null

    companion object{
        fun newGsmMessage(): GsmMessage {
            return GsmMessage()
        }
    }
}




















class Message {
    var securityHeader: SecurityHeader = SecurityHeader()
    var gmmMessage: GmmMessage? = null
    var gsmMessage: GsmMessage? = null

    companion object {
        fun newMessage(): Message {
            return Message()
        }

        const val MsgTypeRegistrationRequest: UByte = (65u)
        const val MsgTypeRegistrationAccept: UByte = (66u)
        const val MsgTypeRegistrationComplete: UByte = (67u)
        const val MsgTypeRegistrationReject: UByte = (68u)
        const val MsgTypeDeregistrationRequestUEOriginatingDeregistration: UByte = (69u)
        const val MsgTypeDeregistrationAcceptUEOriginatingDeregistration: UByte = (70u)
        const val MsgTypeDeregistrationRequestUETerminatedDeregistration: UByte = (71u)
        const val MsgTypeDeregistrationAcceptUETerminatedDeregistration: UByte = (72u)
        const val MsgTypeServiceRequest: UByte = (76u)
        const val MsgTypeServiceReject: UByte = (77u)
        const val MsgTypeServiceAccept: UByte = (78u)
        const val MsgTypeConfigurationUpdateCommand: UByte = (84u)
        const val MsgTypeConfigurationUpdateComplete: UByte = (85u)
        const val MsgTypeAuthenticationRequest: UByte = (86u)
        const val MsgTypeAuthenticationResponse: UByte = (87u)
        const val MsgTypeAuthenticationReject: UByte = (88u)
        const val MsgTypeAuthenticationFailure: UByte = (89u)
        const val MsgTypeAuthenticationResult: UByte = (90u)
        const val MsgTypeIdentityRequest: UByte = (91u)
        const val MsgTypeIdentityResponse: UByte = (92u)
        const val MsgTypeSecurityModeCommand: UByte = (93u)
        const val MsgTypeSecurityModeComplete: UByte = (94u)
        const val MsgTypeSecurityModeReject: UByte = (95u)
        const val MsgTypeStatus5GMM: UByte = (100u)
        const val MsgTypeNotification: UByte = (101u)
        const val MsgTypeNotificationResponse: UByte = (102u)
        const val MsgTypeULNASTransport: UByte = (103u)
        const val MsgTypeDLNASTransport: UByte = (104u)
        const val MsgTypePDUSessionEstablishmentRequest: UByte = (193u)
        const val MsgTypePDUSessionEstablishmentAccept: UByte = (194u)
        const val MsgTypePDUSessionEstablishmentReject: UByte = (195u)
        const val MsgTypePDUSessionAuthenticationCommand: UByte = (197u)
        const val MsgTypePDUSessionAuthenticationComplete: UByte = (198u)
        const val MsgTypePDUSessionAuthenticationResult: UByte = (199u)
        const val MsgTypePDUSessionModificationRequest: UByte = (201u)
        const val MsgTypePDUSessionModificationReject: UByte = (202u)
        const val MsgTypePDUSessionModificationCommand: UByte = (203u)
        const val MsgTypePDUSessionModificationComplete: UByte = (204u)
        const val MsgTypePDUSessionModificationCommandReject: UByte = (205u)
        const val MsgTypePDUSessionReleaseRequest: UByte = (209u)
        const val MsgTypePDUSessionReleaseReject: UByte = (210u)
        const val MsgTypePDUSessionReleaseCommand: UByte = (211u)
        const val MsgTypePDUSessionReleaseComplete: UByte = (212u)
        const val MsgTypeStatus5GSM: UByte = (214u)
    }


    fun plainNasDecode(byteArray: ByteArray) {
        val epd = getEPD(byteArray)
        when (epd) {
            Epd5GSMobilityManagementMessage -> {
                gmmMessageDecode(byteArray)
            }
            Epd5GSSessionManagementMessage -> {
                gsmMessageDecode(byteArray)
            }
            else -> {
                throw Exception("Extended Protocol Discriminator[$epd] is not allowed in Nas Message Decode")
            }
        }
    }

    fun plainNasEncode(): ByteArray? {
        val data = ByteBuffer.allocate(1024)
        if (gmmMessage != null) {
            gmmMessageEncode(data)
        } else if (gsmMessage != null) {
            gsmMessageEncode(data)
        } else {
            return null
        }
        return data.flip().toByteArray()
    }


    fun gmmMessageDecode(byteArray: ByteArray) {
        gmmMessage = GmmMessage.newGmmMessage()

        val buffer = ByteBuffer.wrap(byteArray).order(ByteOrder.BIG_ENDIAN)
        if (buffer.hasRemaining()) {
            val len = gmmMessage!!.gmmHeader.octet.size
            val octets = UByteArray(len) { buffer.get().toUByte() }
            gmmMessage!!.gmmHeader.octet = octets
        } else {
            throw Exception("GMM NAS decode Fail: read fail")
        }

        when (gmmMessage!!.gmmHeader.getMessageType()) {
            MsgTypeRegistrationRequest -> {
                gmmMessage!!.registrationRequest = RegistrationRequest.newRegistrationRequest(MsgTypeRegistrationRequest)
                gmmMessage!!.registrationRequest?.decodeRegistrationRequest(byteArray)
            }
            MsgTypeRegistrationAccept -> {
                gmmMessage!!.registrationAccept = RegistrationAccept.newRegistrationAccept(MsgTypeRegistrationAccept)
                gmmMessage!!.registrationAccept?.decodeRegistrationAccept(byteArray)
            }
            MsgTypeRegistrationComplete -> {
                gmmMessage!!.registrationComplete = RegistrationComplete.newRegistrationComplete(MsgTypeRegistrationComplete)
                gmmMessage!!.registrationComplete?.decodeRegistrationComplete(byteArray)
            }
            MsgTypeRegistrationReject -> {
                gmmMessage!!.registrationReject = RegistrationReject.NewRegistrationReject(MsgTypeRegistrationReject)
                gmmMessage!!.registrationReject?.decodeRegistrationReject(byteArray)
            }
            MsgTypeDeregistrationRequestUEOriginatingDeregistration -> {
                gmmMessage!!.deregistrationRequestUEOriginatingDeregistration =
                    DeregistrationRequestUEOriginatingDeregistration.newDeregistrationRequestUEOriginatingDeregistration(MsgTypeDeregistrationRequestUEOriginatingDeregistration)
                gmmMessage!!.deregistrationRequestUEOriginatingDeregistration?.decodeDeregistrationRequestUEOriginatingDeregistration(byteArray)
            }
            MsgTypeDeregistrationAcceptUEOriginatingDeregistration -> {
                gmmMessage!!.deregistrationAcceptUEOriginatingDeregistration =
                    DeregistrationAcceptUEOriginatingDeregistration.newDeregistrationAcceptUEOriginatingDeregistration(MsgTypeDeregistrationAcceptUEOriginatingDeregistration)
                gmmMessage!!.deregistrationAcceptUEOriginatingDeregistration?.decodeDeregistrationAcceptUEOriginatingDeregistration(byteArray)
            }
            MsgTypeDeregistrationRequestUETerminatedDeregistration -> {
                gmmMessage!!.deregistrationRequestUETerminatedDeregistration =
                    DeregistrationRequestUETerminatedDeregistration.NewDeregistrationRequestUETerminatedDeregistration(MsgTypeDeregistrationRequestUETerminatedDeregistration)
                gmmMessage!!.deregistrationRequestUETerminatedDeregistration?.decodeDeregistrationRequestUETerminatedDeregistration(byteArray)
            }
            MsgTypeDeregistrationAcceptUETerminatedDeregistration -> {
                gmmMessage!!.deregistrationAcceptUETerminatedDeregistration =
                    DeregistrationAcceptUETerminatedDeregistration.newDeregistrationAcceptUETerminatedDeregistration(MsgTypeDeregistrationAcceptUETerminatedDeregistration)
                gmmMessage!!.deregistrationAcceptUETerminatedDeregistration?.decodeDeregistrationAcceptUETerminatedDeregistration(byteArray)
            }
            MsgTypeServiceRequest -> {
                gmmMessage!!.serviceRequest = ServiceRequest.newServiceRequest(MsgTypeServiceRequest)
                gmmMessage!!.serviceRequest?.decodeServiceRequest(byteArray)
            }
            MsgTypeServiceReject -> {
                gmmMessage!!.serviceReject = ServiceReject.newServiceReject(MsgTypeServiceReject)
                gmmMessage!!.serviceReject?.decodeServiceReject(byteArray)
            }
            MsgTypeServiceAccept -> {
                gmmMessage!!.serviceAccept = ServiceAccept.newServiceAccept(MsgTypeServiceAccept)
                gmmMessage!!.serviceAccept?.decodeServiceAccept(byteArray)
            }
            MsgTypeConfigurationUpdateCommand -> {
                gmmMessage!!.configurationUpdateCommand = ConfigurationUpdateCommand.NewConfigurationUpdateCommand(MsgTypeConfigurationUpdateCommand)
                gmmMessage!!.configurationUpdateCommand?.decodeConfigurationUpdateCommand(byteArray)
            }
            MsgTypeConfigurationUpdateComplete -> {
                gmmMessage!!.configurationUpdateComplete = ConfigurationUpdateComplete.newConfigurationUpdateComplete(MsgTypeConfigurationUpdateComplete)
                gmmMessage!!.configurationUpdateComplete?.decodeConfigurationUpdateComplete(byteArray)
            }
            MsgTypeAuthenticationRequest -> {
                gmmMessage!!.authenticationRequest = AuthenticationRequest.newAuthenticationRequest(MsgTypeAuthenticationRequest)
                gmmMessage!!.authenticationRequest!!.decodeAuthenticationRequest(byteArray)
            }
            MsgTypeAuthenticationResponse -> {
                gmmMessage!!.authenticationResponse = AuthenticationResponse.NewAuthenticationResponse(MsgTypeAuthenticationResponse)
                gmmMessage!!.authenticationResponse?.decodeAuthenticationResponse(byteArray)
            }
            MsgTypeAuthenticationReject -> {
                gmmMessage!!.authenticationReject = AuthenticationReject.newAuthenticationReject(MsgTypeAuthenticationReject)
                gmmMessage!!.authenticationReject?.decodeAuthenticationReject(byteArray)
            }
            MsgTypeAuthenticationFailure -> {
                gmmMessage!!.authenticationFailure = AuthenticationFailure.newAuthenticationFailure(MsgTypeAuthenticationFailure)
                gmmMessage!!.authenticationFailure?.decodeAuthenticationFailure(byteArray)
            }
            MsgTypeAuthenticationResult -> {
                gmmMessage!!.authenticationResult = AuthenticationResult.NewAuthenticationResult(MsgTypeAuthenticationResult)
                gmmMessage!!.authenticationResult?.decodeAuthenticationResult(byteArray)
            }
            MsgTypeIdentityRequest -> {
                gmmMessage!!.identityRequest = IdentityRequest.newIdentityRequest(MsgTypeIdentityRequest)
                gmmMessage!!.identityRequest?.decodeIdentityRequest(byteArray)
            }
            MsgTypeIdentityResponse -> {
                gmmMessage!!.identityResponse = IdentityResponse.newIdentityResponse(MsgTypeIdentityResponse)
                gmmMessage!!.identityResponse?.decodeIdentityResponse(byteArray)
            }
            MsgTypeSecurityModeCommand -> {
                gmmMessage!!.securityModeCommand = SecurityModeCommand.newSecurityModeCommand(MsgTypeSecurityModeCommand)
                gmmMessage!!.securityModeCommand?.decodeSecurityModeCommand(byteArray)
            }
            MsgTypeSecurityModeComplete -> {
                gmmMessage!!.securityModeComplete = SecurityModeComplete.NewSecurityModeComplete(MsgTypeSecurityModeComplete)
                gmmMessage!!.securityModeComplete?.decodeSecurityModeComplete(byteArray)
            }
            MsgTypeSecurityModeReject -> {
                gmmMessage!!.securityModeReject = SecurityModeReject.newSecurityModeReject(MsgTypeSecurityModeReject)
                gmmMessage!!.securityModeReject?.decodeSecurityModeReject(byteArray)
            }
            MsgTypeStatus5GMM -> {
                gmmMessage!!.status5GMM = Status5GMM.newStatus5GMM(MsgTypeStatus5GMM)
                gmmMessage!!.status5GMM?.decodeStatus5GMM(byteArray)
            }
            MsgTypeNotification -> {
                gmmMessage!!.notification = Notification.newNotification(MsgTypeNotification)
                gmmMessage!!.notification?.decodeNotification(byteArray)
            }
            MsgTypeNotificationResponse -> {
                gmmMessage!!.notificationResponse = NotificationResponse.NewNotificationResponse(MsgTypeNotificationResponse)
                gmmMessage!!.notificationResponse?.decodeNotificationResponse(byteArray)
            }
            MsgTypeULNASTransport -> {
                gmmMessage!!.ulNASTransport = ULNASTransport.newULNASTransport(MsgTypeULNASTransport)
                gmmMessage!!.ulNASTransport?.decodeULNASTransport(byteArray)
            }
            MsgTypeDLNASTransport -> {
                gmmMessage!!.dlNASTransport = DLNASTransport.NewDLNASTransport(MsgTypeDLNASTransport)
                gmmMessage!!.dlNASTransport?.decodeDLNASTransport(byteArray)
            }
            else -> {
                throw Exception("NAS decode Fail: MsgType[${gmmMessage!!.gmmHeader.getMessageType()}] doesn't exist in GMM Message")
            }
        }
    }

    fun gmmMessageEncode(buffer: ByteBuffer) {
        when (gmmMessage!!.gmmHeader.getMessageType()) {
            MsgTypeRegistrationRequest -> {
                gmmMessage!!.registrationRequest?.encodeRegistrationRequest(buffer)
            }
            MsgTypeRegistrationAccept -> {
                gmmMessage!!.registrationAccept?.encodeRegistrationAccept(buffer)
            }
            MsgTypeRegistrationComplete -> {
                gmmMessage!!.registrationComplete?.encodeRegistrationComplete(buffer)
            }
            MsgTypeRegistrationReject -> {
                gmmMessage!!.registrationReject?.encodeRegistrationReject(buffer)
            }
            MsgTypeDeregistrationRequestUEOriginatingDeregistration -> {
                gmmMessage!!.deregistrationRequestUEOriginatingDeregistration?.encodeDeregistrationRequestUEOriginatingDeregistration(buffer)
            }
            MsgTypeDeregistrationAcceptUEOriginatingDeregistration -> {
                gmmMessage!!.deregistrationAcceptUEOriginatingDeregistration?.encodeDeregistrationAcceptUEOriginatingDeregistration(buffer)
            }
            MsgTypeDeregistrationRequestUETerminatedDeregistration -> {
                gmmMessage!!.deregistrationRequestUETerminatedDeregistration?.encodeDeregistrationRequestUETerminatedDeregistration(buffer)
            }
            MsgTypeDeregistrationAcceptUETerminatedDeregistration -> {
                gmmMessage!!.deregistrationAcceptUETerminatedDeregistration?.encodeDeregistrationAcceptUETerminatedDeregistration(buffer)
            }
            MsgTypeServiceRequest -> {
                gmmMessage!!.serviceRequest?.encodeServiceRequest(buffer)
            }
            MsgTypeServiceReject -> {
                gmmMessage!!.serviceReject?.encodeServiceReject(buffer)
            }
            MsgTypeServiceAccept -> {
                gmmMessage!!.serviceAccept?.encodeServiceAccept(buffer)
            }
            MsgTypeConfigurationUpdateCommand -> {
                gmmMessage!!.configurationUpdateCommand?.encodeConfigurationUpdateCommand(buffer)
            }
            MsgTypeConfigurationUpdateComplete -> {
                gmmMessage!!.configurationUpdateComplete?.encodeConfigurationUpdateComplete(buffer)
            }
            MsgTypeAuthenticationRequest -> {
                gmmMessage!!.authenticationRequest?.encodeAuthenticationRequest(buffer)
            }
            MsgTypeAuthenticationResponse -> {
                gmmMessage!!.authenticationResponse?.encodeAuthenticationResponse(buffer)
            }
            MsgTypeAuthenticationReject -> {
                gmmMessage!!.authenticationReject?.encodeAuthenticationReject(buffer)
            }
            MsgTypeAuthenticationFailure -> {
                gmmMessage!!.authenticationFailure?.encodeAuthenticationFailure(buffer)
            }
            MsgTypeAuthenticationResult -> {
                gmmMessage!!.authenticationResult?.encodeAuthenticationResult(buffer)
            }
            MsgTypeIdentityRequest -> {
                gmmMessage!!.identityRequest?.encodeIdentityRequest(buffer)
            }
            MsgTypeIdentityResponse -> {
                gmmMessage!!.identityResponse?.encodeIdentityResponse(buffer)
            }
            MsgTypeSecurityModeCommand -> {
                gmmMessage!!.securityModeCommand?.encodeSecurityModeCommand(buffer)
            }
            MsgTypeSecurityModeComplete -> {
                gmmMessage!!.securityModeComplete?.encodeSecurityModeComplete(buffer)
            }
            MsgTypeSecurityModeReject -> {
                gmmMessage!!.securityModeReject?.encodeSecurityModeReject(buffer)
            }
            MsgTypeStatus5GMM -> {
                gmmMessage!!.status5GMM?.encodeStatus5GMM(buffer)
            }
            MsgTypeNotification -> {
                gmmMessage!!.notification?.encodeNotification(buffer)
            }
            MsgTypeNotificationResponse -> {
                gmmMessage!!.notificationResponse?.encodeNotificationResponse(buffer)
            }
            MsgTypeULNASTransport -> {
                gmmMessage!!.ulNASTransport?.encodeULNASTransport(buffer)
            }
            MsgTypeDLNASTransport -> {
                gmmMessage!!.dlNASTransport?.encodeDLNASTransport(buffer)
            }
            else -> {
                throw Exception("NAS Encode Fail: MsgType[${gmmMessage!!.gmmHeader.getMessageType()}] doesn't exist in GMM Message")
            }
        }
    }


    fun gsmMessageDecode(byteArray: ByteArray) {
        gsmMessage = GsmMessage.newGsmMessage()

        val buffer = ByteBuffer.wrap(byteArray).order(ByteOrder.BIG_ENDIAN)
        if (buffer.hasRemaining()) {
            val len = gsmMessage!!.gsmHeader.octet.size
            val octets = UByteArray(len) { buffer.get().toUByte() }
            gsmMessage!!.gsmHeader.octet = octets
        } else {
            throw Exception("GSM NAS decode Fail: read fail")
        }

        when (gsmMessage!!.gsmHeader.getMessageType()) {
            MsgTypePDUSessionEstablishmentRequest -> {
                gsmMessage!!.pduSessionEstablishmentRequest = PDUSessionEstablishmentRequest.NewPDUSessionEstablishmentRequest(MsgTypePDUSessionEstablishmentRequest)
                gsmMessage!!.pduSessionEstablishmentRequest?.decodePDUSessionEstablishmentRequest(byteArray)
            }
            MsgTypePDUSessionEstablishmentAccept -> {
                gsmMessage!!.pduSessionEstablishmentAccept = PDUSessionEstablishmentAccept.newPDUSessionEstablishmentAccept(MsgTypePDUSessionEstablishmentAccept)
                gsmMessage!!.pduSessionEstablishmentAccept?.decodePDUSessionEstablishmentAccept(byteArray)
            }
            MsgTypePDUSessionEstablishmentReject -> {
                gsmMessage!!.pduSessionEstablishmentReject = PDUSessionEstablishmentReject.newPDUSessionEstablishmentReject(MsgTypePDUSessionEstablishmentReject)
                gsmMessage!!.pduSessionEstablishmentReject?.decodePDUSessionEstablishmentReject(byteArray)
            }
            MsgTypePDUSessionAuthenticationCommand -> {
                gsmMessage!!.pduSessionAuthenticationCommand = PDUSessionAuthenticationCommand.NewPDUSessionAuthenticationCommand(MsgTypePDUSessionAuthenticationCommand)
                gsmMessage!!.pduSessionAuthenticationCommand?.decodePDUSessionAuthenticationCommand(byteArray)
            }
            MsgTypePDUSessionAuthenticationComplete -> {
                gsmMessage!!.pduSessionAuthenticationComplete = PDUSessionAuthenticationComplete.NewPDUSessionAuthenticationComplete(MsgTypePDUSessionAuthenticationComplete)
                gsmMessage!!.pduSessionAuthenticationComplete?.decodePDUSessionAuthenticationComplete(byteArray)
            }
            MsgTypePDUSessionAuthenticationResult -> {
                gsmMessage!!.pduSessionAuthenticationResult = PDUSessionAuthenticationResult.NewPDUSessionAuthenticationResult(MsgTypePDUSessionAuthenticationResult)
                gsmMessage!!.pduSessionAuthenticationResult?.decodePDUSessionAuthenticationResult(byteArray)
            }
            MsgTypePDUSessionModificationRequest -> {
                gsmMessage!!.pduSessionModificationRequest = PDUSessionModificationRequest.newPDUSessionModificationRequest(MsgTypePDUSessionModificationRequest)
                gsmMessage!!.pduSessionModificationRequest?.decodePDUSessionModificationRequest(byteArray)
            }
            MsgTypePDUSessionModificationReject -> {
                gsmMessage!!.pduSessionModificationReject = PDUSessionModificationReject.NewPDUSessionModificationReject(MsgTypePDUSessionModificationReject)
                gsmMessage!!.pduSessionModificationReject?.decodePDUSessionModificationReject(byteArray)
            }
            MsgTypePDUSessionModificationCommand -> {
                gsmMessage!!.pduSessionModificationCommand = PDUSessionModificationCommand.newPDUSessionModificationCommand(MsgTypePDUSessionModificationCommand)
                gsmMessage!!.pduSessionModificationCommand?.decodePDUSessionModificationCommand(byteArray)
            }
            MsgTypePDUSessionModificationComplete -> {
                gsmMessage!!.pduSessionModificationComplete = PDUSessionModificationComplete.newPDUSessionModificationComplete(MsgTypePDUSessionModificationComplete)
                gsmMessage!!.pduSessionModificationComplete?.decodePDUSessionModificationComplete(byteArray)
            }
            MsgTypePDUSessionModificationCommandReject -> {
                gsmMessage!!.pduSessionModificationCommandReject = PDUSessionModificationCommandReject.NewPDUSessionModificationCommandReject(MsgTypePDUSessionModificationCommandReject)
                gsmMessage!!.pduSessionModificationCommandReject?.decodePDUSessionModificationCommandReject(byteArray)
            }
            MsgTypePDUSessionReleaseRequest -> {
                gsmMessage!!.pduSessionReleaseRequest = PDUSessionReleaseRequest.NewPDUSessionReleaseRequest(MsgTypePDUSessionReleaseRequest)
                gsmMessage!!.pduSessionReleaseRequest?.decodePDUSessionReleaseRequest(byteArray)
            }
            MsgTypePDUSessionReleaseReject -> {
                gsmMessage!!.pduSessionReleaseReject = PDUSessionReleaseReject.NewPDUSessionReleaseReject(MsgTypePDUSessionReleaseReject)
                gsmMessage!!.pduSessionReleaseReject?.decodePDUSessionReleaseReject(byteArray)
            }
            MsgTypePDUSessionReleaseCommand -> {
                gsmMessage!!.pduSessionReleaseCommand = PDUSessionReleaseCommand.newPDUSessionReleaseCommand(MsgTypePDUSessionReleaseCommand)
                gsmMessage!!.pduSessionReleaseCommand?.decodePDUSessionReleaseCommand(byteArray)
            }
            MsgTypePDUSessionReleaseComplete -> {
                gsmMessage!!.pduSessionReleaseComplete = PDUSessionReleaseComplete.NewPDUSessionReleaseComplete(MsgTypePDUSessionReleaseComplete)
                gsmMessage!!.pduSessionReleaseComplete?.decodePDUSessionReleaseComplete(byteArray)
            }
            MsgTypeStatus5GSM -> {
                gsmMessage!!.status5GSM = Status5GSM.newStatus5GSM(MsgTypeStatus5GSM)
                gsmMessage!!.status5GSM?.decodeStatus5GSM(byteArray)
            }
            else -> {
                throw Exception("NAS Decode Fail: MsgType[${gsmMessage!!.gsmHeader.getMessageType()}] doesn't exist in GSM Message")
            }
        }
    }

    fun gsmMessageEncode(buffer: ByteBuffer) {
        when (gsmMessage!!.gsmHeader.getMessageType()) {
            MsgTypePDUSessionEstablishmentRequest -> {
                gsmMessage!!.pduSessionEstablishmentRequest?.encodePDUSessionEstablishmentRequest(buffer)
            }
            MsgTypePDUSessionEstablishmentAccept -> {
                gsmMessage!!.pduSessionEstablishmentAccept?.encodePDUSessionEstablishmentAccept(buffer)
            }
            MsgTypePDUSessionEstablishmentReject -> {
                gsmMessage!!.pduSessionEstablishmentReject?.encodePDUSessionEstablishmentReject(buffer)
            }
            MsgTypePDUSessionAuthenticationCommand -> {
                gsmMessage!!.pduSessionAuthenticationCommand?.encodePDUSessionAuthenticationCommand(buffer)
            }
            MsgTypePDUSessionAuthenticationComplete -> {
                gsmMessage!!.pduSessionAuthenticationComplete?.encodePDUSessionAuthenticationComplete(buffer)
            }
            MsgTypePDUSessionAuthenticationResult -> {
                gsmMessage!!.pduSessionAuthenticationResult?.encodePDUSessionAuthenticationResult(buffer)
            }
            MsgTypePDUSessionModificationRequest -> {
                gsmMessage!!.pduSessionModificationRequest?.encodePDUSessionModificationRequest(buffer)
            }
            MsgTypePDUSessionModificationReject -> {
                gsmMessage!!.pduSessionModificationReject?.encodePDUSessionModificationReject(buffer)
            }
            MsgTypePDUSessionModificationCommand -> {
                gsmMessage!!.pduSessionModificationCommand?.encodePDUSessionModificationCommand(buffer)
            }
            MsgTypePDUSessionModificationComplete -> {
                gsmMessage!!.pduSessionModificationComplete?.encodePDUSessionModificationComplete(buffer)
            }
            MsgTypePDUSessionModificationCommandReject -> {
                gsmMessage!!.pduSessionModificationCommandReject?.encodePDUSessionModificationCommandReject(buffer)
            }
            MsgTypePDUSessionReleaseRequest -> {
                gsmMessage!!.pduSessionReleaseRequest?.encodePDUSessionReleaseRequest(buffer)
            }
            MsgTypePDUSessionReleaseReject -> {
                gsmMessage!!.pduSessionReleaseReject?.encodePDUSessionReleaseReject(buffer)
            }
            MsgTypePDUSessionReleaseCommand -> {
                gsmMessage!!.pduSessionReleaseCommand?.encodePDUSessionReleaseCommand(buffer)
            }
            MsgTypePDUSessionReleaseComplete -> {
                gsmMessage!!.pduSessionReleaseComplete?.encodePDUSessionReleaseComplete(buffer)
            }
            MsgTypeStatus5GSM -> {
                gsmMessage!!.status5GSM?.encodeStatus5GSM(buffer)
            }
            else -> {
                throw Exception("NAS Encode Fail: MsgType[${gsmMessage!!.gsmHeader.getMessageType()}] doesn't exist in GSM Message")
            }
        }
    }
}