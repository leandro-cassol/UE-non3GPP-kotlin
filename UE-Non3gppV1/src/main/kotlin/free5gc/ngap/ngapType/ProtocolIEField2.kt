package free5gc.ngap.ngapType

const val InitialContextSetupRequestIEsPresentNothing = 0
const val InitialContextSetupRequestIEsPresentAMFUENGAPID = 1
const val InitialContextSetupRequestIEsPresentRANUENGAPID = 2
const val InitialContextSetupRequestIEsPresentOldAMF = 3
const val InitialContextSetupRequestIEsPresentUEAggregateMaximumBitRate = 4
const val InitialContextSetupRequestIEsPresentCoreNetworkAssistanceInformation = 5
const val InitialContextSetupRequestIEsPresentGUAMI = 6
const val InitialContextSetupRequestIEsPresentPDUSessionResourceSetupListCxtReq = 7
const val InitialContextSetupRequestIEsPresentAllowedNSSAI = 8
const val InitialContextSetupRequestIEsPresentUESecurityCapabilities = 9
const val InitialContextSetupRequestIEsPresentSecurityKey = 10
const val InitialContextSetupRequestIEsPresentTraceActivation = 11
const val InitialContextSetupRequestIEsPresentMobilityRestrictionList = 12
const val InitialContextSetupRequestIEsPresentUERadioCapability = 13
const val InitialContextSetupRequestIEsPresentIndexToRFSP = 14
const val InitialContextSetupRequestIEsPresentMaskedIMEISV = 15
const val InitialContextSetupRequestIEsPresentNASPDU = 16
const val InitialContextSetupRequestIEsPresentEmergencyFallbackIndicator = 17
const val InitialContextSetupRequestIEsPresentRRCInactiveTransitionReportRequest = 18
const val InitialContextSetupRequestIEsPresentUERadioCapabilityForPaging = 19
const val InitialContextSetupRequestIEsPresentRedirectionVoiceFallback = 20

data class InitialContextSetupRequestIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val oldAMF: AMFName?,
    val ueAggregateMaximumBitRate: UEAggregateMaximumBitRate?,
    val coreNetworkAssistanceInformation: CoreNetworkAssistanceInformation?,
    val guami: GUAMI?,
    val pduSessionResourceSetupListCxtReq: PDUSessionResourceSetupListCxtReq?,
    val allowedNSSAI: AllowedNSSAI?,
    val ueSecurityCapabilities: UESecurityCapabilities?,
    val securityKey: SecurityKey?,
    val traceActivation: TraceActivation?,
    val mobilityRestrictionList: MobilityRestrictionList?,
    val ueRadioCapability: UERadioCapability?,
    val indexToRFSP: IndexToRFSP?,
    val maskedIMEISV: MaskedIMEISV?,
    val naspdu: NASPDU?,
    val emergencyFallbackIndicator: EmergencyFallbackIndicator?,
    val rrcInactiveTransitionReportRequest: RRCInactiveTransitionReportRequest?,
    val ueRadioCapabilityForPaging: UERadioCapabilityForPaging?,
    val redirectionVoiceFallback: RedirectionVoiceFallback?
)

data class InitialContextSetupResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: InitialContextSetupResponseIEsValue
)

const val InitialContextSetupResponseIEsPresentNothing = 0
const val InitialContextSetupResponseIEsPresentAMFUENGAPID = 1
const val InitialContextSetupResponseIEsPresentRANUENGAPID = 2
const val InitialContextSetupResponseIEsPresentPDUSessionResourceSetupListCxtRes = 3
const val InitialContextSetupResponseIEsPresentPDUSessionResourceFailedToSetupListCxtRes = 4
const val InitialContextSetupResponseIEsPresentCriticalityDiagnostics = 5

data class InitialContextSetupResponseIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val pduSessionResourceSetupListCxtRes: PDUSessionResourceSetupListCxtRes?,
    val pduSessionResourceFailedToSetupListCxtRes: PDUSessionResourceFailedToSetupListCxtRes?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class InitialContextSetupFailureIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: InitialContextSetupFailureIEsValue
)

const val InitialContextSetupFailureIEsPresentNothing = 0
const val InitialContextSetupFailureIEsPresentAMFUENGAPID = 1
const val InitialContextSetupFailureIEsPresentRANUENGAPID = 2
const val InitialContextSetupFailureIEsPresentPDUSessionResourceFailedToSetupListCxtFail = 3
const val InitialContextSetupFailureIEsPresentCause = 4
const val InitialContextSetupFailureIEsPresentCriticalityDiagnostics = 5

data class InitialContextSetupFailureIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val pduSessionResourceFailedToSetupListCxtFail: PDUSessionResourceFailedToSetupListCxtFail?,
    val cause: Cause?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class UEContextReleaseRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UEContextReleaseRequestIEsValue
)

const val UEContextReleaseRequestIEsPresentNothing = 0
const val UEContextReleaseRequestIEsPresentAMFUENGAPID = 1
const val UEContextReleaseRequestIEsPresentRANUENGAPID = 2
const val UEContextReleaseRequestIEsPresentPDUSessionResourceListCxtRelReq = 3
const val UEContextReleaseRequestIEsPresentCause = 4

data class UEContextReleaseRequestIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val pduSessionResourceListCxtRelReq: PDUSessionResourceListCxtRelReq?,
    val cause: Cause?
)

data class UEContextReleaseCommandIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UEContextReleaseCommandIEsValue
)

const val UEContextReleaseCommandIEsPresentNothing = 0
const val UEContextReleaseCommandIEsPresentUENGAPIDs = 1
const val UEContextReleaseCommandIEsPresentCause = 2

data class UEContextReleaseCommandIEsValue(
    val present: Int,
    val uengapids: UENGAPIDs?,
    val cause: Cause?
)

data class UEContextReleaseCompleteIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UEContextReleaseCompleteIEsValue
)

const val UEContextReleaseCompleteIEsPresentNothing = 0
const val UEContextReleaseCompleteIEsPresentAMFUENGAPID = 1
const val UEContextReleaseCompleteIEsPresentRANUENGAPID = 2
const val UEContextReleaseCompleteIEsPresentUserLocationInformation = 3
const val UEContextReleaseCompleteIEsPresentInfoOnRecommendedCellsAndRANNodesForPaging = 4
const val UEContextReleaseCompleteIEsPresentPDUSessionResourceListCxtRelCpl = 5
const val UEContextReleaseCompleteIEsPresentCriticalityDiagnostics = 6

data class UEContextReleaseCompleteIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val userLocationInformation: UserLocationInformation?,
    val infoOnRecommendedCellsAndRANNodesForPaging: InfoOnRecommendedCellsAndRANNodesForPaging?,
    val pduSessionResourceListCxtRelCpl: PDUSessionResourceListCxtRelCpl?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class UEContextModificationRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UEContextModificationRequestIEsValue
)

const val UEContextModificationRequestIEsPresentNothing = 0
const val UEContextModificationRequestIEsPresentAMFUENGAPID = 1
const val UEContextModificationRequestIEsPresentRANUENGAPID = 2
const val UEContextModificationRequestIEsPresentRANPagingPriority = 3
const val UEContextModificationRequestIEsPresentSecurityKey = 4
const val UEContextModificationRequestIEsPresentIndexToRFSP = 5
const val UEContextModificationRequestIEsPresentUEAggregateMaximumBitRate = 6
const val UEContextModificationRequestIEsPresentUESecurityCapabilities = 7
const val UEContextModificationRequestIEsPresentCoreNetworkAssistanceInformation = 8
const val UEContextModificationRequestIEsPresentEmergencyFallbackIndicator = 9
const val UEContextModificationRequestIEsPresentNewAMFUENGAPID = 10
const val UEContextModificationRequestIEsPresentRRCInactiveTransitionReportRequest = 11

data class UEContextModificationRequestIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val ranPagingPriority: RANPagingPriority?,
    val securityKey: SecurityKey?,
    val indexToRFSP: IndexToRFSP?,
    val ueAggregateMaximumBitRate: UEAggregateMaximumBitRate?,
    val ueSecurityCapabilities: UESecurityCapabilities?,
    val coreNetworkAssistanceInformation: CoreNetworkAssistanceInformation?,
    val emergencyFallbackIndicator: EmergencyFallbackIndicator?,
    val newAMFUENGAPID: AMFUENGAPID?,
    val rrcInactiveTransitionReportRequest: RRCInactiveTransitionReportRequest?
)

data class UEContextModificationResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UEContextModificationResponseIEsValue
)

const val UEContextModificationResponseIEsPresentNothing = 0
const val UEContextModificationResponseIEsPresentAMFUENGAPID = 1
const val UEContextModificationResponseIEsPresentRANUENGAPID = 2
const val UEContextModificationResponseIEsPresentRRCState = 3
const val UEContextModificationResponseIEsPresentUserLocationInformation = 4
const val UEContextModificationResponseIEsPresentCriticalityDiagnostics = 5

data class UEContextModificationResponseIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val rrcState: RRCState?,
    val userLocationInformation: UserLocationInformation?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class UEContextModificationFailureIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UEContextModificationFailureIEsValue
)

const val UEContextModificationFailureIEsPresentNothing = 0
const val UEContextModificationFailureIEsPresentAMFUENGAPID = 1
const val UEContextModificationFailureIEsPresentRANUENGAPID = 2
const val UEContextModificationFailureIEsPresentCause = 3
const val UEContextModificationFailureIEsPresentCriticalityDiagnostics = 4

data class UEContextModificationFailureIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val cause: Cause?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class RRCInactiveTransitionReportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: RRCInactiveTransitionReportIEsValue
)

const val RRCInactiveTransitionReportIEsPresentNothing = 1
const val RRCInactiveTransitionReportIEsPresentAMFUENGAPID = 2
const val RRCInactiveTransitionReportIEsPresentRANUENGAPID = 3
const val RRCInactiveTransitionReportIEsPresentRRCState = 4
const val RRCInactiveTransitionReportIEsPresentUserLocationInformation = 5

data class RRCInactiveTransitionReportIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val rrcState: RRCState?,
    val userLocationInformation: UserLocationInformation?
)

data class HandoverRequiredIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverRequiredIEsValue
)

const val HandoverRequiredIEsPresentNothing = 0
const val HandoverRequiredIEsPresentAMFUENGAPID = 1
const val HandoverRequiredIEsPresentRANUENGAPID = 2
const val HandoverRequiredIEsPresentHandoverType = 3
const val HandoverRequiredIEsPresentCause = 4
const val HandoverRequiredIEsPresentTargetID = 5
const val HandoverRequiredIEsPresentDirectForwardingPathAvailability = 6
const val HandoverRequiredIEsPresentPDUSessionResourceListHORqd = 7
const val HandoverRequiredIEsPresentSourceToTargetTransparentContainer = 8

data class HandoverRequiredIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val handoverType: HandoverType?,
    val cause: Cause?,
    val targetID: TargetID?,
    val directForwardingPathAvailability: DirectForwardingPathAvailability?,
    val pduSessionResourceListHORqd: PDUSessionResourceListHORqd?,
    val sourceToTargetTransparentContainer: SourceToTargetTransparentContainer?
)

data class HandoverCommandIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverCommandIEsValue
)

const val HandoverCommandIEsPresentNothing = 0
const val HandoverCommandIEsPresentAMFUENGAPID = 1
const val HandoverCommandIEsPresentRANUENGAPID = 2
const val HandoverCommandIEsPresentHandoverType = 3
const val HandoverCommandIEsPresentNASSecurityParametersFromNGRAN = 4
const val HandoverCommandIEsPresentPDUSessionResourceHandoverList = 5
const val HandoverCommandIEsPresentPDUSessionResourceToReleaseListHOCmd = 6
const val HandoverCommandIEsPresentTargetToSourceTransparentContainer = 7
const val HandoverCommandIEsPresentCriticalityDiagnostics = 8

data class HandoverCommandIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val handoverType: HandoverType?,
    val nasSecurityParametersFromNGRAN: NASSecurityParametersFromNGRAN?,
    val pduSessionResourceHandoverList: PDUSessionResourceHandoverList?,
    val pduSessionResourceToReleaseListHOCmd: PDUSessionResourceToReleaseListHOCmd?,
    val targetToSourceTransparentContainer: TargetToSourceTransparentContainer?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class HandoverPreparationFailureIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverPreparationFailureIEsValue
)

const val HandoverPreparationFailureIEsPresentNothing = 0
const val HandoverPreparationFailureIEsPresentAMFUENGAPID = 1
const val HandoverPreparationFailureIEsPresentRANUENGAPID = 2
const val HandoverPreparationFailureIEsPresentCause = 3
const val HandoverPreparationFailureIEsPresentCriticalityDiagnostics = 4

data class HandoverPreparationFailureIEsValue(
    val present: Int,
    val amfUENGAPID: AMFUENGAPID?,
    val ranUENGAPID: RANUENGAPID?,
    val cause: Cause?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class HandoverRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverRequestIEsValue
)

const val HandoverRequestIEsPresentNothing = 0
const val HandoverRequestIEsPresentAMFUENGAPID = 1
const val HandoverRequestIEsPresentHandoverType = 2
const val HandoverRequestIEsPresentCause = 3
const val HandoverRequestIEsPresentUEAggregateMaximumBitRate = 4
const val HandoverRequestIEsPresentCoreNetworkAssistanceInformation = 5
const val HandoverRequestIEsPresentUESecurityCapabilities = 6
const val HandoverRequestIEsPresentSecurityContext = 7
const val HandoverRequestIEsPresentNewSecurityContextInd = 8
const val HandoverRequestIEsPresentNASC = 9
const val HandoverRequestIEsPresentPDUSessionResourceSetupListHOReq = 10
const val HandoverRequestIEsPresentAllowedNSSAI = 11
const val HandoverRequestIEsPresentTraceActivation = 12
const val HandoverRequestIEsPresentMaskedIMEISV = 13
const val HandoverRequestIEsPresentSourceToTargetTransparentContainer = 14
const val HandoverRequestIEsPresentMobilityRestrictionList = 15
const val HandoverRequestIEsPresentLocationReportingRequestType = 16
const val HandoverRequestIEsPresentRRCInactiveTransitionReportRequest = 17
const val HandoverRequestIEsPresentGUAMI = 18
const val HandoverRequestIEsPresentRedirectionVoiceFallback = 19


