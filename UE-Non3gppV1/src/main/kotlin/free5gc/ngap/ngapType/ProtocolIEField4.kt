package free5gc.ngap.ngapType

data class RerouteNASRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: RerouteNASRequestIEsValue
)

const val RerouteNASRequestIEsPresentNothing = 0
const val RerouteNASRequestIEsPresentRANUENGAPID = 1
const val RerouteNASRequestIEsPresentAMFUENGAPID = 2
const val RerouteNASRequestIEsPresentNGAPMessage = 3
const val RerouteNASRequestIEsPresentAMFSetID = 4
const val RerouteNASRequestIEsPresentAllowedNSSAI = 5

data class RerouteNASRequestIEsValue(
    val present: Int,
    val ranuengapid: RANUENGAPID?,
    val amfuengapid: AMFUENGAPID?,
    val ngapmessage: ByteArray?,
    val amfsetid: AMFSetID?,
    val allowednssai: AllowedNSSAI?
)

data class NGSetupRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: NGSetupRequestIEsValue
)

const val NGSetupRequestIEsPresentNothing = 0
const val NGSetupRequestIEsPresentGlobalRANNodeID = 1
const val NGSetupRequestIEsPresentRANNodeName = 2
const val NGSetupRequestIEsPresentSupportedTAList = 3
const val NGSetupRequestIEsPresentDefaultPagingDRX = 4
const val NGSetupRequestIEsPresentUERetentionInformation = 5

data class NGSetupRequestIEsValue(
    val present: Int,
    val globalrannodeid: GlobalRANNodeID?,
    val rannodename: RANNodeName?,
    val supportedtalist: SupportedTAList?,
    val defaultpagingdrx: PagingDRX?,
    val ueretentioninformation: UERetentionInformation?
)

data class NGSetupResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: NGSetupResponseIEsValue
)

const val NGSetupResponseIEsPresentNothing = 0
const val NGSetupResponseIEsPresentAMFName = 1
const val NGSetupResponseIEsPresentServedGUAMIList = 2
const val NGSetupResponseIEsPresentRelativeAMFCapacity = 3
const val NGSetupResponseIEsPresentPLMNSupportList = 4
const val NGSetupResponseIEsPresentCriticalityDiagnostics = 5
const val NGSetupResponseIEsPresentUERetentionInformation = 6

data class NGSetupResponseIEsValue(
    val present: Int,
    val amfname: AMFName?,
    val servedguamilist: ServedGUAMIList?,
    val relativeamfcapacity: RelativeAMFCapacity?,
    val plmnsupportlist: PLMNSupportList?,
    val criticalitydiagnostics: CriticalityDiagnostics?,
    val ueretentioninformation: UERetentionInformation?
)

data class NGSetupFailureIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: NGSetupFailureIEsValue
)

const val NGSetupFailureIEsPresentNothing = 0
const val NGSetupFailureIEsPresentCause = 1
const val NGSetupFailureIEsPresentTimeToWait = 2
const val NGSetupFailureIEsPresentCriticalityDiagnostics = 3

data class NGSetupFailureIEsValue(
    val present: Int,
    val cause: Cause?,
    val timetowait: TimeToWait?,
    val criticalitydiagnostics: CriticalityDiagnostics?
)

data class RANConfigurationUpdateIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: RANConfigurationUpdateIEsValue
)

const val RANConfigurationUpdateIEsPresentNothing = 0
const val RANConfigurationUpdateIEsPresentRANNodeName = 1
const val RANConfigurationUpdateIEsPresentSupportedTAList = 2
const val RANConfigurationUpdateIEsPresentDefaultPagingDRX = 3
const val RANConfigurationUpdateIEsPresentGlobalRANNodeID = 4

data class RANConfigurationUpdateIEsValue(
    val present: Int,
    val rannodename: RANNodeName?,
    val supportedtalist: SupportedTAList?,
    val defaultpagingdrx: PagingDRX?,
    val globalrannodeid: GlobalRANNodeID?
)

data class RANConfigurationUpdateAcknowledgeIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: RANConfigurationUpdateAcknowledgeIEsValue
)

const val RANConfigurationUpdateAcknowledgeIEsPresentNothing = 0
const val RANConfigurationUpdateAcknowledgeIEsPresentCriticalityDiagnostics = 1

data class RANConfigurationUpdateAcknowledgeIEsValue(
    val present: Int,
    val criticalitydiagnostics: CriticalityDiagnostics?
)

data class RANConfigurationUpdateFailureIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: RANConfigurationUpdateFailureIEsValue
)

const val RANConfigurationUpdateFailureIEsPresentNothing = 0
const val RANConfigurationUpdateFailureIEsPresentCause = 1
const val RANConfigurationUpdateFailureIEsPresentTimeToWait = 2
const val RANConfigurationUpdateFailureIEsPresentCriticalityDiagnostics = 3

data class RANConfigurationUpdateFailureIEsValue(
    val present: Int,
    val cause: Cause?,
    val timetowait: TimeToWait?,
    val criticalitydiagnostics: CriticalityDiagnostics?
)

data class AMFConfigurationUpdateIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: AMFConfigurationUpdateIEsValue
)

const val AMFConfigurationUpdateIEsPresentNothing = 0
const val AMFConfigurationUpdateIEsPresentAMFName = 1
const val AMFConfigurationUpdateIEsPresentServedGUAMIList = 2
const val AMFConfigurationUpdateIEsPresentRelativeAMFCapacity = 3
const val AMFConfigurationUpdateIEsPresentPLMNSupportList = 4
const val AMFConfigurationUpdateIEsPresentAMFTNLAssociationToAddList = 5
const val AMFConfigurationUpdateIEsPresentAMFTNLAssociationToRemoveList = 6
const val AMFConfigurationUpdateIEsPresentAMFTNLAssociationToUpdateList = 7

data class AMFConfigurationUpdateIEsValue(
    val present: Int,
    val amfname: AMFName?,
    val servedguamilist: ServedGUAMIList?,
    val relativeamfcapacity: RelativeAMFCapacity?,
    val plmnsupportlist: PLMNSupportList?,
    val amftnlassociationtoaddlist: AMFTNLAssociationToAddList?,
    val amftnlassociationtoremovelist: AMFTNLAssociationToRemoveList?,
    val amftnlassociationtoupdatelist: AMFTNLAssociationToUpdateList?
)

data class AMFConfigurationUpdateAcknowledgeIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: AMFConfigurationUpdateAcknowledgeIEsValue
)

const val AMFConfigurationUpdateAcknowledgeIEsPresentNothing = 0
const val AMFConfigurationUpdateAcknowledgeIEsPresentAMFTNLAssociationSetupList = 1
const val AMFConfigurationUpdateAcknowledgeIEsPresentAMFTNLAssociationFailedToSetupList = 2
const val AMFConfigurationUpdateAcknowledgeIEsPresentCriticalityDiagnostics = 3

data class AMFConfigurationUpdateAcknowledgeIEsValue(
    val present: Int,
    val amftnlassociationsetuplist: AMFTNLAssociationSetupList?,
    val amftnlassociationfailedtosetuplist: TNLAssociationList?,
    val criticalitydiagnostics: CriticalityDiagnostics?
)

data class AMFConfigurationUpdateFailureIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: AMFConfigurationUpdateFailureIEsValue
)

const val AMFConfigurationUpdateFailureIEsPresentNothing = 0
const val AMFConfigurationUpdateFailureIEsPresentCause = 1
const val AMFConfigurationUpdateFailureIEsPresentTimeToWait = 2
const val AMFConfigurationUpdateFailureIEsPresentCriticalityDiagnostics = 3

data class AMFConfigurationUpdateFailureIEsValue(
    val present: Int,
    val cause: Cause?,
    val timetowait: TimeToWait?,
    val criticalitydiagnostics: CriticalityDiagnostics?
)

data class AMFStatusIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: AMFStatusIndicationIEsValue
)

const val AMFStatusIndicationIEsPresentNothing = 0
const val AMFStatusIndicationIEsPresentUnavailableGUAMIList = 1

data class AMFStatusIndicationIEsValue(
    val present: Int,
    val unavailableguamilist: UnavailableGUAMIList?
)

data class NGResetIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: NGResetIEsValue
)

const val NGResetIEsPresentNothing = 0
const val NGResetIEsPresentCause = 1
const val NGResetIEsPresentResetType = 2

data class NGResetIEsValue(
    val present: Int,
    val cause: Cause?,
    val resettype: ResetType?
)

data class NGResetAcknowledgeIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: NGResetAcknowledgeIEsValue
)

const val NGResetAcknowledgeIEsPresentNothing = 0
const val NGResetAcknowledgeIEsPresentUEAssociatedLogicalNGConnectionList = 1
const val NGResetAcknowledgeIEsPresentCriticalityDiagnostics = 2

data class NGResetAcknowledgeIEsValue(
    val present: Int,
    val ueassociatedlogicalngconnectionlist: UEAssociatedLogicalNGConnectionList?,
    val criticalitydiagnostics: CriticalityDiagnostics?
)

data class ErrorIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: ErrorIndicationIEsValue
)

const val ErrorIndicationIEsPresentNothing = 0
const val ErrorIndicationIEsPresentAMFUENGAPID = 1
const val ErrorIndicationIEsPresentRANUENGAPID = 2
const val ErrorIndicationIEsPresentCause = 3
const val ErrorIndicationIEsPresentCriticalityDiagnostics = 4

data class ErrorIndicationIEsValue(
    val present: Int,
    val amfuengapid: AMFUENGAPID?,
    val ranuengapid: RANUENGAPID?,
    val cause: Cause?,
    val criticalitydiagnostics: CriticalityDiagnostics?
)

data class OverloadStartIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: OverloadStartIEsValue
)

const val OverloadStartIEsPresentNothing = 0
const val OverloadStartIEsPresentAMFOverloadResponse = 1
const val OverloadStartIEsPresentAMFTrafficLoadReductionIndication = 2
const val OverloadStartIEsPresentOverloadStartNSSAIList = 3

data class OverloadStartIEsValue(
    val present: Int,
    val amfoverloadresponse: OverloadResponse?,
    val amftrafficloadreductionindication: TrafficLoadReductionIndication?,
    val overloadstartnssailist: OverloadStartNSSAIList?
)

data class OverloadStopIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: OverloadStopIEsValue
)

const val OverloadStopIEsPresentNothing = 0

data class OverloadStopIEsValue(
    val present: Int
)

data class UplinkRANConfigurationTransferIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UplinkRANConfigurationTransferIEsValue
)

const val UplinkRANConfigurationTransferIEsPresentNothing = 0
const val UplinkRANConfigurationTransferIEsPresentSONConfigurationTransferUL = 1
const val UplinkRANConfigurationTransferIEsPresentENDCSONConfigurationTransferUL = 2

data class UplinkRANConfigurationTransferIEsValue(
    val present: Int,
    val sonconfigurationtransferul: SONConfigurationTransfer?,
    val endcsonconfigurationtransferul: ENDCSONConfigurationTransfer?
)

data class DownlinkRANConfigurationTransferIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: DownlinkRANConfigurationTransferIEsValue
)

const val DownlinkRANConfigurationTransferIEsPresentNothing = 0
const val DownlinkRANConfigurationTransferIEsPresentSONConfigurationTransferDL = 1
const val DownlinkRANConfigurationTransferIEsPresentENDCSONConfigurationTransferDL = 2

data class DownlinkRANConfigurationTransferIEsValue(
    val present: Int,
    val sonconfigurationtransferdl: SONConfigurationTransfer?,
    val endcsonconfigurationtransferdl: ENDCSONConfigurationTransfer?
)

data class WriteReplaceWarningRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: WriteReplaceWarningRequestIEsValue
)

const val WriteReplaceWarningRequestIEsPresentNothing = 0
const val WriteReplaceWarningRequestIEsPresentMessageIdentifier = 1
const val WriteReplaceWarningRequestIEsPresentSerialNumber = 2
const val WriteReplaceWarningRequestIEsPresentWarningAreaList = 3
const val WriteReplaceWarningRequestIEsPresentRepetitionPeriod = 4
const val WriteReplaceWarningRequestIEsPresentNumberOfBroadcastsRequested = 5
const val WriteReplaceWarningRequestIEsPresentWarningType = 6
const val WriteReplaceWarningRequestIEsPresentWarningSecurityInfo = 7
const val WriteReplaceWarningRequestIEsPresentDataCodingScheme = 8
const val WriteReplaceWarningRequestIEsPresentWarningMessageContents = 9
const val WriteReplaceWarningRequestIEsPresentConcurrentWarningMessageInd = 10
const val WriteReplaceWarningRequestIEsPresentWarningAreaCoordinates = 11

data class WriteReplaceWarningRequestIEsValue(
    val present: Int,
    val messageidentifier: MessageIdentifier?,
    val serialnumber: SerialNumber?,
    val warningarealist: WarningAreaList?,
    val repetitionperiod: RepetitionPeriod?,
    val numberofbroadcastsrequested: NumberOfBroadcastsRequested?,
    val warningtype: WarningType?,
    val warningsecurityinfo: WarningSecurityInfo?,
    val datacodingscheme: DataCodingScheme?,
    val warningmessagecontents: WarningMessageContents?,
    val concurrentwarningmessageind: ConcurrentWarningMessageInd?,
    val warningareacoordinates: WarningAreaCoordinates?
)

data class WriteReplaceWarningResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: WriteReplaceWarningResponseIEsValue
)

const val WriteReplaceWarningResponseIEsPresentNothing = 0
const val WriteReplaceWarningResponseIEsPresentMessageIdentifier = 1
const val WriteReplaceWarningResponseIEsPresentSerialNumber = 2
const val WriteReplaceWarningResponseIEsPresentBroadcastCompletedAreaList = 3
const val WriteReplaceWarningResponseIEsPresentCriticalityDiagnostics = 4

data class WriteReplaceWarningResponseIEsValue(
    val present: Int,
    val messageidentifier: MessageIdentifier?,
    val serialnumber: SerialNumber?,
    val broadcastcompletedarealist: BroadcastCompletedAreaList?,
    val criticalitydiagnostics: CriticalityDiagnostics?
)

data class PWSCancelRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PWSCancelRequestIEsValue
)

const val PWSCancelRequestIEsPresentNothing = 0
const val PWSCancelRequestIEsPresentMessageIdentifier = 1
const val PWSCancelRequestIEsPresentSerialNumber = 2
const val PWSCancelRequestIEsPresentWarningAreaList = 3
const val PWSCancelRequestIEsPresentCancelAllWarningMessages = 4

data class PWSCancelRequestIEsValue(
    val present: Int,
    val messageidentifier: MessageIdentifier?,
    val serialnumber: SerialNumber?,
    val warningarealist: WarningAreaList?,
    val cancelallwarningmessages: CancelAllWarningMessages?
)

data class PWSCancelResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PWSCancelResponseIEsValue
)

const val PWSCancelResponseIEsPresentNothing = 0
const val PWSCancelResponseIEsPresentMessageIdentifier = 1
const val PWSCancelResponseIEsPresentSerialNumber = 2
const val PWSCancelResponseIEsPresentBroadcastCancelledAreaList = 3
const val PWSCancelResponseIEsPresentCriticalityDiagnostics = 4

data class PWSCancelResponseIEsValue(
    val present: Int,
    val messageidentifier: MessageIdentifier?,
    val serialnumber: SerialNumber?,
    val broadcastcancelledarealist: BroadcastCancelledAreaList?,
    val criticalitydiagnostics: CriticalityDiagnostics?
)


