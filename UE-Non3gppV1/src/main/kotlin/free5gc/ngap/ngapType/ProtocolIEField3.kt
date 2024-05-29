package free5gc.ngap.ngapType

data class HandoverRequestIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val handoverType: HandoverType?,
    val cause: Cause?,
    val ueAggregateMaximumBitRate: UEAggregateMaximumBitRate?,
    val coreNetworkAssistanceInformation: CoreNetworkAssistanceInformation?,
    val ueSecurityCapabilities: UESecurityCapabilities?,
    val securityContext: SecurityContext?,
    val newSecurityContextInd: NewSecurityContextInd?,
    val nasc: NASPDU?,
    val pduSessionResourceSetupListHOReq: PDUSessionResourceSetupListHOReq?,
    val allowedNSSAI: AllowedNSSAI?,
    val traceActivation: TraceActivation?,
    val maskedIMEISV: MaskedIMEISV?,
    val sourceToTargetTransparentContainer: SourceToTargetTransparentContainer?,
    val mobilityRestrictionList: MobilityRestrictionList?,
    val locationReportingRequestType: LocationReportingRequestType?,
    val rrcInactiveTransitionReportRequest: RRCInactiveTransitionReportRequest?,
    val guami: GUAMI?,
    val redirectionVoiceFallback: RedirectionVoiceFallback?
)

data class HandoverRequestAcknowledgeIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverRequestAcknowledgeIEsValue
)

const val HandoverRequestAcknowledgeIEsPresentNothing = 0
const val HandoverRequestAcknowledgeIEsPresentAMFUENGAPID = 1
const val HandoverRequestAcknowledgeIEsPresentRANUENGAPID = 2
const val HandoverRequestAcknowledgeIEsPresentPDUSessionResourceAdmittedList = 3
const val HandoverRequestAcknowledgeIEsPresentPDUSessionResourceFailedToSetupListHOAck = 4
const val HandoverRequestAcknowledgeIEsPresentTargetToSourceTransparentContainer = 5
const val HandoverRequestAcknowledgeIEsPresentCriticalityDiagnostics = 6

data class HandoverRequestAcknowledgeIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val pduSessionResourceAdmittedList: PDUSessionResourceAdmittedList?,
    val pduSessionResourceFailedToSetupListHOAck: PDUSessionResourceFailedToSetupListHOAck?,
    val targetToSourceTransparentContainer: TargetToSourceTransparentContainer?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class HandoverFailureIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverFailureIEsValue
)

const val HandoverFailureIEsPresentNothing = 0
const val HandoverFailureIEsPresentAMFUENGAPID = 1
const val HandoverFailureIEsPresentCause = 2
const val HandoverFailureIEsPresentCriticalityDiagnostics = 3

data class HandoverFailureIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val cause: Cause?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class HandoverNotifyIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverNotifyIEsValue
)

const val HandoverNotifyIEsPresentNothing = 0
const val HandoverNotifyIEsPresentAMFUENGAPID = 1
const val HandoverNotifyIEsPresentRANUENGAPID = 2
const val HandoverNotifyIEsPresentUserLocationInformation = 3

data class HandoverNotifyIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val userLocationInformation: UserLocationInformation?
)

data class PathSwitchRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PathSwitchRequestIEsValue
)

const val PathSwitchRequestIEsPresentNothing = 0
const val PathSwitchRequestIEsPresentRANUENGAPID = 1
const val PathSwitchRequestIEsPresentSourceAMFUENGAPID = 2
const val PathSwitchRequestIEsPresentUserLocationInformation = 3
const val PathSwitchRequestIEsPresentUESecurityCapabilities = 4
const val PathSwitchRequestIEsPresentPDUSessionResourceToBeSwitchedDLList = 5
const val PathSwitchRequestIEsPresentPDUSessionResourceFailedToSetupListPSReq = 6

data class PathSwitchRequestIEsValue(
    val present: Int,
    val ranuengapid: RANUENGAPID?,
    val sourceAMFUENGAPID: AMFUENGAPID?,
    val userLocationInformation: UserLocationInformation?,
    val ueSecurityCapabilities: UESecurityCapabilities?,
    val pduSessionResourceToBeSwitchedDLList: PDUSessionResourceToBeSwitchedDLList?,
    val pduSessionResourceFailedToSetupListPSReq: PDUSessionResourceFailedToSetupListPSReq?
)

data class PathSwitchRequestAcknowledgeIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PathSwitchRequestAcknowledgeIEsValue
)

const val PathSwitchRequestAcknowledgeIEsPresentNothing = 0
const val PathSwitchRequestAcknowledgeIEsPresentAMFUENGAPID = 1
const val PathSwitchRequestAcknowledgeIEsPresentRANUENGAPID = 2
const val PathSwitchRequestAcknowledgeIEsPresentUESecurityCapabilities = 3
const val PathSwitchRequestAcknowledgeIEsPresentSecurityContext = 4
const val PathSwitchRequestAcknowledgeIEsPresentNewSecurityContextInd = 5
const val PathSwitchRequestAcknowledgeIEsPresentPDUSessionResourceSwitchedList = 6
const val PathSwitchRequestAcknowledgeIEsPresentPDUSessionResourceReleasedListPSAck = 7
const val PathSwitchRequestAcknowledgeIEsPresentAllowedNSSAI = 8
const val PathSwitchRequestAcknowledgeIEsPresentCoreNetworkAssistanceInformation = 9
const val PathSwitchRequestAcknowledgeIEsPresentRRCInactiveTransitionReportRequest = 10
const val PathSwitchRequestAcknowledgeIEsPresentCriticalityDiagnostics = 11
const val PathSwitchRequestAcknowledgeIEsPresentRedirectionVoiceFallback = 12

data class PathSwitchRequestAcknowledgeIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val ueSecurityCapabilities: UESecurityCapabilities?,
    val securityContext: SecurityContext?,
    val newSecurityContextInd: NewSecurityContextInd?,
    val pduSessionResourceSwitchedList: PDUSessionResourceSwitchedList?,
    val pduSessionResourceReleasedListPSAck: PDUSessionResourceReleasedListPSAck?,
    val allowedNSSAI: AllowedNSSAI?,
    val coreNetworkAssistanceInformation: CoreNetworkAssistanceInformation?,
    val rrcInactiveTransitionReportRequest: RRCInactiveTransitionReportRequest?,
    val criticalityDiagnostics: CriticalityDiagnostics?,
    val redirectionVoiceFallback: RedirectionVoiceFallback?
)

data class PathSwitchRequestFailureIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PathSwitchRequestFailureIEsValue
)

const val PathSwitchRequestFailureIEsPresentNothing = 0
const val PathSwitchRequestFailureIEsPresentAMFUENGAPID = 1
const val PathSwitchRequestFailureIEsPresentRANUENGAPID = 2
const val PathSwitchRequestFailureIEsPresentPDUSessionResourceReleasedListPSFail = 3
const val PathSwitchRequestFailureIEsPresentCriticalityDiagnostics = 4

data class PathSwitchRequestFailureIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val pduSessionResourceReleasedListPSFail: PDUSessionResourceReleasedListPSFail?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class HandoverCancelIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverCancelIEsValue
)

const val HandoverCancelIEsPresentNothing = 0
const val HandoverCancelIEsPresentAMFUENGAPID = 1
const val HandoverCancelIEsPresentRANUENGAPID = 2
const val HandoverCancelIEsPresentCause = 3

data class HandoverCancelIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val cause: Cause?
)

data class HandoverCancelAcknowledgeIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: HandoverCancelAcknowledgeIEsValue
)

const val HandoverCancelAcknowledgeIEsPresentNothing = 0
const val HandoverCancelAcknowledgeIEsPresentAMFUENGAPID = 1
const val HandoverCancelAcknowledgeIEsPresentRANUENGAPID = 2
const val HandoverCancelAcknowledgeIEsPresentCriticalityDiagnostics = 3

data class HandoverCancelAcknowledgeIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class UplinkRANStatusTransferIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UplinkRANStatusTransferIEsValue
)

const val UplinkRANStatusTransferIEsPresentNothing = 0
const val UplinkRANStatusTransferIEsPresentAMFUENGAPID = 1
const val UplinkRANStatusTransferIEsPresentRANUENGAPID = 2
const val UplinkRANStatusTransferIEsPresentRANStatusTransferTransparentContainer = 3

data class UplinkRANStatusTransferIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val ranStatusTransferTransparentContainer: RANStatusTransferTransparentContainer?
)

data class DownlinkRANStatusTransferIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: DownlinkRANStatusTransferIEsValue
)

const val DownlinkRANStatusTransferIEsPresentNothing = 0
const val DownlinkRANStatusTransferIEsPresentAMFUENGAPID = 1
const val DownlinkRANStatusTransferIEsPresentRANUENGAPID = 2
const val DownlinkRANStatusTransferIEsPresentRANStatusTransferTransparentContainer = 3

data class DownlinkRANStatusTransferIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val ranStatusTransferTransparentContainer: RANStatusTransferTransparentContainer?
)

data class PagingIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PagingIEsValue
)

const val PagingIEsPresentNothing = 0
const val PagingIEsPresentUEPagingIdentity = 1
const val PagingIEsPresentPagingDRX = 2
const val PagingIEsPresentTAIListForPaging = 3
const val PagingIEsPresentPagingPriority = 4
const val PagingIEsPresentUERadioCapabilityForPaging = 5
const val PagingIEsPresentPagingOrigin = 6
const val PagingIEsPresentAssistanceDataForPaging = 7

data class PagingIEsValue(
    val present: Int,
    val uePagingIdentity: UEPagingIdentity?,
    val pagingDRX: PagingDRX?,
    val taiListForPaging: TAIListForPaging?,
    val pagingPriority: PagingPriority?,
    val ueRadioCapabilityForPaging: UERadioCapabilityForPaging?,
    val pagingOrigin: PagingOrigin?,
    val assistanceDataForPaging: AssistanceDataForPaging?
)

data class InitialUEMessageIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: InitialUEMessageIEsValue
)

const val InitialUEMessageIEsPresentNothing = 0
const val InitialUEMessageIEsPresentRANUENGAPID = 1
const val InitialUEMessageIEsPresentNASPDU = 2
const val InitialUEMessageIEsPresentUserLocationInformation = 3
const val InitialUEMessageIEsPresentRRCEstablishmentCause = 4
const val InitialUEMessageIEsPresentFiveGSTMSI = 5
const val InitialUEMessageIEsPresentAMFSetID = 6
const val InitialUEMessageIEsPresentUEContextRequest = 7
const val InitialUEMessageIEsPresentAllowedNSSAI = 8

data class InitialUEMessageIEsValue(
    val present: Int,
    val ranuengapid: RANUENGAPID?,
    val naspdu: NASPDU?,
    val userLocationInformation: UserLocationInformation?,
    val rrcEstablishmentCause: RRCEstablishmentCause?,
    val fiveGSTMSI: FiveGSTMSI?,
    val amfSetID: AMFSetID?,
    val ueContextRequest: UEContextRequest?,
    val allowedNSSAI: AllowedNSSAI?
)

data class DownlinkNASTransportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: DownlinkNASTransportIEsValue
)

const val DownlinkNASTransportIEsPresentNothing = 0
const val DownlinkNASTransportIEsPresentAMFUENGAPID = 1
const val DownlinkNASTransportIEsPresentRANUENGAPID = 2
const val DownlinkNASTransportIEsPresentOldAMF = 3
const val DownlinkNASTransportIEsPresentRANPagingPriority = 4
const val DownlinkNASTransportIEsPresentNASPDU = 5
const val DownlinkNASTransportIEsPresentMobilityRestrictionList = 6
const val DownlinkNASTransportIEsPresentIndexToRFSP = 7
const val DownlinkNASTransportIEsPresentUEAggregateMaximumBitRate = 8
const val DownlinkNASTransportIEsPresentAllowedNSSAI = 9

data class DownlinkNASTransportIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val oldAMF: AMFName?,
    val ranPagingPriority: RANPagingPriority?,
    val naspdu: NASPDU?,
    val mobilityRestrictionList: MobilityRestrictionList?,
    val indexToRFSP: IndexToRFSP?,
    val ueAggregateMaximumBitRate: UEAggregateMaximumBitRate?,
    val allowedNSSAI: AllowedNSSAI?
)

data class UplinkNASTransportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UplinkNASTransportIEsValue
)

const val UplinkNASTransportIEsPresentNothing = 0
const val UplinkNASTransportIEsPresentAMFUENGAPID = 1
const val UplinkNASTransportIEsPresentRANUENGAPID = 2
const val UplinkNASTransportIEsPresentNASPDU = 3
const val UplinkNASTransportIEsPresentUserLocationInformation = 4

data class UplinkNASTransportIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val naspdu: NASPDU?,
    val userLocationInformation: UserLocationInformation?
)

data class NASNonDeliveryIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: NASNonDeliveryIndicationIEsValue
)

const val NASNonDeliveryIndicationIEsPresentNothing = 0
const val NASNonDeliveryIndicationIEsPresentAMFUENGAPID = 1
const val NASNonDeliveryIndicationIEsPresentRANUENGAPID = 2
const val NASNonDeliveryIndicationIEsPresentNASPDU = 3
const val NASNonDeliveryIndicationIEsPresentCause = 4

data class NASNonDeliveryIndicationIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val naspdu: NASPDU?,
    val cause: Cause?
)


