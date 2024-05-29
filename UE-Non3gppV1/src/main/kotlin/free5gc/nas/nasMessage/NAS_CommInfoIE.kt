package free5gc.nas.nasMessage

class CommInfoIE {

    companion object {
        const val ULNASTransportRequestTypeInitialRequest: UByte = 1u
        const val ULNASTransportRequestTypeExistingPduSession: UByte = 2u
        const val ULNASTransportRequestTypeInitialEmergencyRequest: UByte = 3u
        const val ULNASTransportRequestTypeExistingEmergencyPduSession: UByte = 4u
        const val ULNASTransportRequestTypeModificationRequest: UByte = 5u
        const val ULNASTransportRequestTypeReserved: UByte = 7u

        const val PayloadContainerTypeN1SMInfo: UByte = 0x01u
        const val PayloadContainerTypeSMS: UByte = 0x02u
        const val PayloadContainerTypeLPP: UByte = 0x03u
        const val PayloadContainerTypeSOR: UByte = 0x04u
        const val PayloadContainerTypeUEPolicy: UByte = 0x05u
        const val PayloadContainerTypeUEParameterUpdate: UByte = 0x06u
        const val PayloadContainerTypeMultiplePayload: UByte = 0x0Fu

        const val Cause5GSMInsufficientResources: UByte = 0x1au
        const val Cause5GSMMissingOrUnknownDNN: UByte = 0x1bu
        const val Cause5GSMUnknownPDUSessionType: UByte = 0x1cu
        const val Cause5GSMUserAuthenticationOrAuthorizationFailed: UByte = 0x1du
        const val Cause5GSMRequestRejectedUnspecified: UByte = 0x1fu
        const val Cause5GSMServiceOptionTemporarilyOutOfOrder: UByte = 0x22u
        const val Cause5GSMPTIAlreadyInUse: UByte = 0x23u
        const val Cause5GSMRegularDeactivation: UByte = 0x24u
        const val Cause5GSMNetworkFailure: UByte = 0x26u
        const val Cause5GSMReactivationRequested: UByte = 0x27u
        const val Cause5GSMInvalidPDUSessionIdentity: UByte = 0x2bu
        const val Cause5GSMSemanticErrorsInPacketFilter: UByte = 0x2cu
        const val Cause5GSMSyntacticalErrorInPacketFilter: UByte = 0x2du
        const val Cause5GSMOutOfLADNServiceArea: UByte = 0x2eu
        const val Cause5GSMPTIMismatch: UByte = 0x2fu
        const val Cause5GSMPDUSessionTypeIPv4OnlyAllowed: UByte = 0x32u
        const val Cause5GSMPDUSessionTypeIPv6OnlyAllowed: UByte = 0x33u
        const val Cause5GSMPDUSessionDoesNotExist: UByte = 0x36u
        const val Cause5GSMInsufficientResourcesForSpecificSliceAndDNN: UByte = 0x43u
        const val Cause5GSMNotSupportedSSCMode: UByte = 0x44u
        const val Cause5GSMInsufficientResourcesForSpecificSlice: UByte = 0x45u
        const val Cause5GSMMissingOrUnknownDNNInASlice: UByte = 0x46u
        const val Cause5GSMInvalidPTIValue: UByte = 0x51u
        const val Cause5GSMMaximumDataRatePerUEForUserPlaneIntegrityProtectionIsTooLow: UByte = 0x52u
        const val Cause5GSMSemanticErrorInTheQoSOperation: UByte = 0x53u
        const val Cause5GSMSyntacticalErrorInTheQoSOperation: UByte = 0x54u
        const val Cause5GSMInvalidMappedEPSBearerIdentity: UByte = 0x55u
        const val Cause5GSMSemanticallyIncorrectMessage: UByte = 0x5fu
        const val Cause5GSMInvalidMandatoryInformation: UByte = 0x60u
        const val Cause5GSMMessageTypeNonExistentOrNotImplemented: UByte = 0x61u
        const val Cause5GSMMessageTypeNotCompatibleWithTheProtocolState: UByte = 0x62u
        const val Cause5GSMInformationElementNonExistentOrNotImplemented: UByte = 0x63u
        const val Cause5GSMConditionalIEError: UByte = 0x64u
        const val Cause5GSMMessageNotCompatibleWithTheProtocolState: UByte = 0x65u
        const val Cause5GSMProtocolErrorUnspecified: UByte = 0x6fu

        const val Cause5GMMIllegalUE: UByte = 0x03u
        const val Cause5GMMPEINotAccepted: UByte = 0x05u
        const val Cause5GMMIllegalME: UByte = 0x06u
        const val Cause5GMM5GSServicesNotAllowed: UByte = 0x07u
        const val Cause5GMMUEIdentityCannotBeDerivedByTheNetwork: UByte = 0x09u
        const val Cause5GMMImplicitlyDeregistered: UByte = 0x0au
        const val Cause5GMMPLMNNotAllowed: UByte = 0x0bu
        const val Cause5GMMTrackingAreaNotAllowed: UByte = 0x0cu
        const val Cause5GMMRoamingNotAllowedInThisTrackingArea: UByte = 0x0du
        const val Cause5GMMNoSuitableCellsInTrackingArea: UByte = 0x0fu
        const val Cause5GMMMACFailure: UByte = 0x14u
        const val Cause5GMMSynchFailure: UByte = 0x15u
        const val Cause5GMMCongestion: UByte = 0x16u
        const val Cause5GMMSecurityCapabilitiesMismatch: UByte = 0x17u
        const val Cause5GMMSecurityModeRejectedUnspecified: UByte = 0x18u
        const val Cause5GMMNon5GAuthenticationUnacceptable: UByte = 0x1au
        const val Cause5GMMN1ModeNotAllowed: UByte = 0x1bu
        const val Cause5GMMRestrictedServiceArea: UByte = 0x1cu
        const val Cause5GMMLADNNotAvailable: UByte = 0x2bu
        const val Cause5GMMMaximumNumberOfPDUSessionsReached: UByte = 0x41u
        const val Cause5GMMInsufficientResourcesForSpecificSliceAndDNN: UByte = 0x43u
        const val Cause5GMMInsufficientResourcesForSpecificSlice: UByte = 0x45u
        const val Cause5GMMngKSIAlreadyInUse: UByte = 0x47u
        const val Cause5GMMNon3GPPAccessTo5GCNNotAllowed: UByte = 0x48u
        const val Cause5GMMServingNetworkNotAuthorized: UByte = 0x49u
        const val Cause5GMMPayloadWasNotForwarded: UByte = 0x5au
        const val Cause5GMMDNNNotSupportedOrNotSubscribedInTheSlice: UByte = 0x5bu
        const val Cause5GMMInsufficientUserPlaneResourcesForThePDUSession: UByte = 0x5cu
        const val Cause5GMMSemanticallyIncorrectMessage: UByte = 0x5fu
        const val Cause5GMMInvalidMandatoryInformation: UByte = 0x60u
        const val Cause5GMMMessageTypeNonExistentOrNotImplemented: UByte = 0x61u
        const val Cause5GMMMessageTypeNotCompatibleWithTheProtocolState: UByte = 0x62u
        const val Cause5GMMInformationElementNonExistentOrNotImplemented: UByte = 0x63u
        const val Cause5GMMConditionalIEError: UByte = 0x64u
        const val Cause5GMMMessageNotCompatibleWithTheProtocolState: UByte = 0x65u
        const val Cause5GMMProtocolErrorUnspecified: UByte = 0x6fu

        const val RegistrationType5GSInitialRegistration: UByte = 0x01u
        const val RegistrationType5GSMobilityRegistrationUpdating: UByte = 0x02u
        const val RegistrationType5GSPeriodicRegistrationUpdating: UByte = 0x03u
        const val RegistrationType5GSEmergencyRegistration: UByte = 0x04u
        const val RegistrationType5GSReserved: UByte = 0x07u

        const val FollowOnRequestNoPending: UByte = 0x00u
        const val FollowOnRequestPending: UByte = 0x01u

        const val MobileIdentity5GSTypeNoIdentity: UByte = 0x00u
        const val MobileIdentity5GSTypeSuci: UByte = 0x01u
        const val MobileIdentity5GSType5gGuti: UByte = 0x02u
        const val MobileIdentity5GSTypeImei: UByte = 0x03u
        const val MobileIdentity5GSType5gSTmsi: UByte = 0x04u
        const val MobileIdentity5GSTypeImeisv: UByte = 0x05u

        const val DRXValueNotSpecified: UByte = 0x00u
        const val DRXcycleParameterT32: UByte = 0x01u
        const val DRXcycleParameterT64: UByte = 0x02u
        const val DRXcycleParameterT128: UByte = 0x03u
        const val DRXcycleParameterT256: UByte = 0x04u

        // TS 24.501 9.11.3.32
        const val TypeOfSecurityContextFlagNative: UByte = 0x00u
        const val TypeOfSecurityContextFlagMapped: UByte = 0x01u

        // TS 24.501 9.11.3.32
        const val NasKeySetIdentifierNoKeyIsAvailable: Int = 0x07

        // TS 24.501 9.11.3.11
        const val AccessType3GPP: UByte = 0x01u
        const val AccessTypeNon3GPP: UByte = 0x02u
        const val AccessTypeBoth: UByte = 0x03u

        const val ServiceTypeSignalling: UByte = 0x00u
        const val ServiceTypeData: UByte = 0x01u
        const val ServiceTypeMobileTerminatedServices: UByte = 0x02u
        const val ServiceTypeEmergencyServices: UByte = 0x03u
        const val ServiceTypeEmergencyServicesFallback: UByte = 0x04u
        const val ServiceTypeHighPriorityAccess: UByte = 0x05u

        // TS 24.501 9.11.3.20
        const val ReRegistrationNotRequired: UByte = 0x00u
        const val ReRegistrationRequired: UByte = 0x01u

        // TS 24.501 9.11.3.28 TS 24.008 10.5.5.10
        const val IMEISVNotRequested: UByte = 0x00u
        const val IMEISVRequested: UByte = 0x01u

        // TS 24.501 9.11.3.6
        const val RegistrationResult5GS3GPPAccess: UByte = 0x01u
        const val RegistrationResult5GSNon3GPPAccess: UByte = 0x02u
        const val RegistrationResult5GS3GPPandNon3GPPAccess: UByte = 0x03u

        const val SMSOverNasNotAllowed: UByte = 0x00u
        const val SMSOverNasAllowed: UByte = 0x01u

        // TS 24.501 9.11.3.46
        const val SnssaiNotAvailableInCurrentPlmn: UByte = 0x00u
        const val SnssaiNotAvailableInCurrentRegistrationArea: UByte = 0x01u

        // TS 24.008 10.5.7.4a
        const val GPRSTimer3UnitMultiplesOf10Minutes: UByte = 0x00u
        const val GPRSTimer3UnitMultiplesOf1Hour: UByte = 0x01u
        const val GPRSTimer3UnitMultiplesOf10Hours: UByte = 0x02u
        const val GPRSTimer3UnitMultiplesOf2Seconds: UByte = 0x03u
        const val GPRSTimer3UnitMultiplesOf30Seconds: UByte = 0x04u
        const val GPRSTimer3UnitMultiplesOf1Minute: UByte = 0x05u

        // TS 24.501 9.11.3.9A
        const val NGRanRadioCapabilityUpdateNotNeeded: UByte = 0x00u
        const val NGRanRadioCapabilityUpdateNeeded: UByte = 0x01u

        // TS 24.501 9.11.3.49
        const val AllowedTypeAllowedArea: UByte = 0x00u
        const val AllowedTypeNonAllowedArea: UByte = 0x01u

        // TS 24.501 9.11.3.46
        const val RejectedSnssaiCauseNotAvailableInCurrentPlmn: UByte = 0x00u
        const val RejectedSnssaiCauseNotAvailableInCurrentRegistrationArea: UByte = 0x01u

        // TS 24.501 9.11.4.10
        const val PDUSessionTypeIPv4: UByte = 0x01u
        const val PDUSessionTypeIPv6: UByte = 0x02u
        const val PDUSessionTypeIPv4IPv6: UByte = 0x03u
        const val PDUSessionTypeUnstructured: UByte = 0x04u
        const val PDUSessionTypeEthernet: UByte = 0x05u

        // TS 24.501 9.11.3.4
        const val SupiFormatImsi: UByte = 0x00u
        const val SupiFormatNai: UByte = 0x01u

        // TS 24.501 9.11.3.4
        const val ProtectionSchemeNullScheme: Int = 0
        const val ProtectionSchemeECIESProfileA: Int = 1
        const val ProtectionSchemeECIESProfileB: Int = 2

        const val SessionAMBRUnitNotUsed: UByte = 0x00u
        const val SessionAMBRUnit1Kbps: UByte = 0x01u
        const val SessionAMBRUnit4Kbps: UByte = 0x02u
        const val SessionAMBRUnit16Kbps: UByte = 0x03u
        const val SessionAMBRUnit64Kbps: UByte = 0x04u
        const val SessionAMBRUnit256Kbps: UByte = 0x05u
        const val SessionAMBRUnit1Mbps: UByte = 0x06u
        const val SessionAMBRUnit4Mbps: UByte = 0x07u
        const val SessionAMBRUnit16Mbps: UByte = 0x08u
        const val SessionAMBRUnit64Mbps: UByte = 0x09u
        const val SessionAMBRUnit256Mbps: UByte = 0x0Au
        const val SessionAMBRUnit1Gbps: UByte = 0x0Bu
        const val SessionAMBRUnit4Gbps: UByte = 0x0Cu
        const val SessionAMBRUnit16Gbps: UByte = 0x0Du
        const val SessionAMBRUnit64Gbps: UByte = 0x0Eu
        const val SessionAMBRUnit256Gbps: UByte = 0x0Fu
        const val SessionAMBRUnit1Tbps: UByte = 0x10u
        const val SessionAMBRUnit4Tbps: UByte = 0x11u
        const val SessionAMBRUnit16Tbps: UByte = 0x12u
        const val SessionAMBRUnit64Tbps: UByte = 0x13u
        const val SessionAMBRUnit256Tbps: UByte = 0x14u
        const val SessionAMBRUnit1Pbps: UByte = 0x15u
        const val SessionAMBRUnit4Pbps: UByte = 0x16u
        const val SessionAMBRUnit16Pbps: UByte = 0x17u
        const val SessionAMBRUnit64Pbps: UByte = 0x18u
        const val SessionAMBRUnit256Pbps: UByte = 0x19u

        const val PCSCFIPv6AddressRequestUL: UShort = 0x0001u
        const val IMCNSubsystemSignalingFlagUL: UShort = 0x0002u
        const val DNSServerIPv6AddressRequestUL: UShort = 0x0003u
        const val NotSupportedUL: UShort = 0x0004u
        const val MSSupportOfNetworkRequestedBearerControlIndicatorUL: UShort = 0x0005u
        const val DSMIPv6HomeAgentAddressRequestUL: UShort = 0x0007u
        const val DSMIPv6HomeNetworkPrefixRequestUL: UShort = 0x0008u
        const val DSMIPv6IPv4HomeAgentAddressRequestUL: UShort = 0x0009u
        const val IPAddressAllocationViaNASSignallingUL: UShort = 0x000Au
        const val IPv4AddressAllocationViaDHCPv4UL: UShort = 0x000Bu
        const val PCSCFIPv4AddressRequestUL: UShort = 0x000Cu
        const val DNSServerIPv4AddressRequestUL: UShort = 0x000Du
        const val MSISDNRequestUL: UShort = 0x000Eu
        const val IFOMSupportRequestUL: UShort = 0x000Fu
        const val IPv4LinkMTURequestUL: UShort = 0x0010u
        const val MSSupportOfLocalAddressInTFTIndicatorUL: UShort = 0x0011u
        const val PCSCFReSelectionSupportUL: UShort = 0x0012u
        const val NBIFOMRequestIndicatorUL: UShort = 0x0013u
        const val NBIFOMModeUL: UShort = 0x0014u
        const val NonIPLinkMTURequestUL: UShort = 0x0015u
        const val APNRateControlSupportIndicatorUL: UShort = 0x0016u
        const val UEStatus3GPPPSDataOffUL: UShort = 0x0017u
        const val ReliableDataServiceRequestIndicatorUL: UShort = 0x0018u
        const val AdditionalAPNRateControlForExceptionDataSupportIndicatorUL: UShort = 0x0019u
        const val PDUSessionIDUL: UShort = 0x001Au
        const val EthernetFramePayloadMTURequestUL: UShort = 0x0020u
        const val UnstructuredLinkMTURequestUL: UShort = 0x0021u
        const val I5GSMCauseValueUL: UShort = 0x0022u
        const val QoSRulesWithTheLengthOfTwoOctetsSupportIndicatorUL: UShort = 0x0023u
        const val QoSFlowDescriptionsWithTheLengthOfTwoOctetsSupportIndicatorUL: UShort = 0x0024u
        const val LinkControlProtocolUL: UShort = 0xc021u
        const val PushAccessControlProtocolUL: UShort = 0xc023u
        const val ChallengeHandshakeAuthenticationProtocolUL: UShort = 0xc223u
        const val InternetProtocolControlProtocolUL: UShort = 0x8021u

        const val PCSCFIPv6AddressDL: UShort = 0x0001u
        const val IMCNSubsystemSignalingFlagDL: UShort = 0x0002u
        const val DNSServerIPv6AddressDL: UShort = 0x0003u
        const val PolicyControlRejectionCodeDL: UShort = 0x0004u
        const val SelectedBearerControlModeDL: UShort = 0x0005u
        const val DSMIPv6HomeAgentAddressDL: UShort = 0x0007u
        const val DSMIPv6HomeNetworkPrefixDL: UShort = 0x0008u
        const val DSMIPv6IPv4HomeAgentAddressDL: UShort = 0x0009u
        const val PCSCFIPv4AddressDL: UShort = 0x000Cu
        const val DNSServerIPv4AddressDL: UShort = 0x000Du
        const val MSISDNDL: UShort = 0x000Eu
        const val IFOMSupportDL: UShort = 0x000Fu
        const val IPv4LinkMTUDL: UShort = 0x0010u
        const val NetworkSupportOfLocaladdressInTFTIndicatorDL: UShort = 0x0011u
        const val NBIFOMAcceptedIndicatorDL: UShort = 0x0013u
        const val NBIFOMModeDL: UShort = 0x0014u
        const val NonIPLinkMTUDL: UShort = 0x0015u
        const val APNRateControlParametersDL: UShort = 0x0016u
        const val Indication3GPPPSDataOffSupportDL: UShort = 0x0017u
        const val ReliableDataServiceAcceptedIndicatorDL: UShort = 0x0018u
        const val AdditionalAPNRateControlForExceptionDataParametersDL: UShort = 0x0019u
        const val SNSSAIDL: UShort = 0x001bu
        const val QoSRulesDL: UShort = 0x001cu
        const val SessionAMBRDL: UShort = 0x001du
        const val PDUSessionAddressLifetimeDL: UShort = 0x001eu
        const val QoSFlowDescriptions: UShort = 0x001fu
        const val EthernetFramePayloadMTU: UShort = 0x0020u
        const val UnstructuredLinkMTU: UShort = 0x0021u
        const val QoSRulesWithTheLengthOfTwoOctets: UShort = 0x0023u
        const val QoSFlowDescriptionsWithTheLengthOfTwoOctets: UShort = 0x0024u

    }

    fun cause5GMMToString(cause: UByte): String {
        return when (cause) {
            Cause5GMMIllegalUE -> "Illegal UE ($Cause5GMMIllegalUE)"
            Cause5GMMPEINotAccepted -> "PEI not accepted ($Cause5GMMPEINotAccepted)"
            Cause5GMMIllegalME -> "Illegal ME ($Cause5GMMIllegalME)"
            Cause5GMM5GSServicesNotAllowed -> "5GS services not allowed ($Cause5GMM5GSServicesNotAllowed)"
            Cause5GMMUEIdentityCannotBeDerivedByTheNetwork -> "UE identity cannot be derived by the network ($Cause5GMMUEIdentityCannotBeDerivedByTheNetwork)"
            Cause5GMMImplicitlyDeregistered -> "Implicitly deregistered ($Cause5GMMImplicitlyDeregistered)"
            Cause5GMMPLMNNotAllowed -> "PLMN not allowed ($Cause5GMMPLMNNotAllowed)"
            Cause5GMMTrackingAreaNotAllowed -> "Tracking area not allowed ($Cause5GMMTrackingAreaNotAllowed)"
            Cause5GMMRoamingNotAllowedInThisTrackingArea -> "Roaming not allowed in this tracking area ($Cause5GMMRoamingNotAllowedInThisTrackingArea)"
            Cause5GMMNoSuitableCellsInTrackingArea -> "No suitable cells in tracking area ($Cause5GMMNoSuitableCellsInTrackingArea)"
            Cause5GMMMACFailure -> "MAC failure ($Cause5GMMMACFailure)"
            Cause5GMMSynchFailure -> "Synch failure ($Cause5GMMSynchFailure)"
            Cause5GMMCongestion -> "Congestion ($Cause5GMMCongestion)"
            Cause5GMMSecurityCapabilitiesMismatch -> "UE security capabilities mismatch ($Cause5GMMSecurityCapabilitiesMismatch)"
            Cause5GMMSecurityModeRejectedUnspecified -> "Security mode rejected, upspecified ($Cause5GMMSecurityModeRejectedUnspecified)"
            Cause5GMMNon5GAuthenticationUnacceptable -> "Non 5G authentication unacceptable ($Cause5GMMNon5GAuthenticationUnacceptable)"
            Cause5GMMN1ModeNotAllowed -> "N1 mode not allowed ($Cause5GMMN1ModeNotAllowed)"
            Cause5GMMRestrictedServiceArea -> "Restricted service area ($Cause5GMMRestrictedServiceArea)"
            Cause5GMMLADNNotAvailable -> "LADN not available ($Cause5GMMLADNNotAvailable)"
            Cause5GMMMaximumNumberOfPDUSessionsReached -> "Maximum number of PDU sessions reached ($Cause5GMMMaximumNumberOfPDUSessionsReached)"
            Cause5GMMInsufficientResourcesForSpecificSliceAndDNN -> "Insufficient resources for specific slice and DNN ($Cause5GMMInsufficientResourcesForSpecificSliceAndDNN)"
            Cause5GMMInsufficientResourcesForSpecificSlice -> "Insufficient resources for specific slice ($Cause5GMMInsufficientResourcesForSpecificSlice)"
            Cause5GMMngKSIAlreadyInUse -> "ngKSI already in use ($Cause5GMMngKSIAlreadyInUse)"
            Cause5GMMNon3GPPAccessTo5GCNNotAllowed -> "Non-3GPP access to 5GCN not allowed ($Cause5GMMNon3GPPAccessTo5GCNNotAllowed)"
            Cause5GMMServingNetworkNotAuthorized -> "Serving network not authorized ($Cause5GMMServingNetworkNotAuthorized)"
            Cause5GMMPayloadWasNotForwarded -> "Payload was not forwarded ($Cause5GMMPayloadWasNotForwarded)"
            Cause5GMMDNNNotSupportedOrNotSubscribedInTheSlice -> "DNN not supported or not subscribed in the slice ($Cause5GMMDNNNotSupportedOrNotSubscribedInTheSlice)"
            Cause5GMMInsufficientUserPlaneResourcesForThePDUSession -> "Insufficient user plane resources for the PDU session ($Cause5GMMInsufficientUserPlaneResourcesForThePDUSession)"
            Cause5GMMSemanticallyIncorrectMessage -> "Semantically incorrect message ($Cause5GMMSemanticallyIncorrectMessage)"
            Cause5GMMInvalidMandatoryInformation -> "Invalid mandatory information ($Cause5GMMInvalidMandatoryInformation)"
            Cause5GMMMessageTypeNonExistentOrNotImplemented -> "Message type non existent or not implemented ($Cause5GMMMessageTypeNonExistentOrNotImplemented)"
            Cause5GMMMessageTypeNotCompatibleWithTheProtocolState -> "Message type not compatible with the protocol state ($Cause5GMMMessageTypeNotCompatibleWithTheProtocolState)"
            Cause5GMMInformationElementNonExistentOrNotImplemented -> "Information element non existent or not implemented ($Cause5GMMInformationElementNonExistentOrNotImplemented)"
            Cause5GMMConditionalIEError -> "Conditional IE error ($Cause5GMMConditionalIEError)"
            Cause5GMMMessageNotCompatibleWithTheProtocolState -> "Message not compatible with the protocol state ($Cause5GMMMessageNotCompatibleWithTheProtocolState)"
            Cause5GMMProtocolErrorUnspecified -> "Protocol error unspecified ($Cause5GMMProtocolErrorUnspecified)"
            else -> ""
        }
    }
}


