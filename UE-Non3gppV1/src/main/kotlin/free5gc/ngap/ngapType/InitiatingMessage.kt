package free5gc.ngap.ngapType

data class InitiatingMessage(
    val procedureCode: ProcedureCode,
    val criticality: Criticality,
    val value: InitiatingMessageValue
)

const val InitiatingMessagePresentNothing = 0
const val InitiatingMessagePresentAMFConfigurationUpdate = 1
const val InitiatingMessagePresentHandoverCancel = 2
const val InitiatingMessagePresentHandoverRequired = 3
const val InitiatingMessagePresentHandoverRequest = 4
const val InitiatingMessagePresentInitialContextSetupRequest = 5
const val InitiatingMessagePresentNGReset = 6
const val InitiatingMessagePresentNGSetupRequest = 7
const val InitiatingMessagePresentPathSwitchRequest = 8
const val InitiatingMessagePresentPDUSessionResourceModifyRequest = 9
const val InitiatingMessagePresentPDUSessionResourceModifyIndication = 10
const val InitiatingMessagePresentPDUSessionResourceReleaseCommand = 11
const val InitiatingMessagePresentPDUSessionResourceSetupRequest = 12
const val InitiatingMessagePresentPWSCancelRequest = 13
const val InitiatingMessagePresentRANConfigurationUpdate = 14
const val InitiatingMessagePresentUEContextModificationRequest = 15
const val InitiatingMessagePresentUEContextReleaseCommand = 16
const val InitiatingMessagePresentUERadioCapabilityCheckRequest = 17
const val InitiatingMessagePresentWriteReplaceWarningRequest = 18
const val InitiatingMessagePresentAMFStatusIndication = 19
const val InitiatingMessagePresentCellTrafficTrace = 20
const val InitiatingMessagePresentDeactivateTrace = 21
const val InitiatingMessagePresentDownlinkNASTransport = 22
const val InitiatingMessagePresentDownlinkNonUEAssociatedNRPPaTransport = 23
const val InitiatingMessagePresentDownlinkRANConfigurationTransfer = 24
const val InitiatingMessagePresentDownlinkRANStatusTransfer = 25
const val InitiatingMessagePresentDownlinkUEAssociatedNRPPaTransport = 26
const val InitiatingMessagePresentErrorIndication = 27
const val InitiatingMessagePresentHandoverNotify = 28
const val InitiatingMessagePresentInitialUEMessage = 29
const val InitiatingMessagePresentLocationReport = 30
const val InitiatingMessagePresentLocationReportingControl = 31
const val InitiatingMessagePresentLocationReportingFailureIndication = 32
const val InitiatingMessagePresentNASNonDeliveryIndication = 33
const val InitiatingMessagePresentOverloadStart = 34
const val InitiatingMessagePresentOverloadStop = 35
const val InitiatingMessagePresentPaging = 36
const val InitiatingMessagePresentPDUSessionResourceNotify = 37
const val InitiatingMessagePresentPrivateMessage = 38
const val InitiatingMessagePresentPWSFailureIndication = 39
const val InitiatingMessagePresentPWSRestartIndication = 40
const val InitiatingMessagePresentRerouteNASRequest = 41
const val InitiatingMessagePresentRRCInactiveTransitionReport = 42
const val InitiatingMessagePresentSecondaryRATDataUsageReport = 43
const val InitiatingMessagePresentTraceFailureIndication = 44
const val InitiatingMessagePresentTraceStart = 45
const val InitiatingMessagePresentUEContextReleaseRequest = 46
const val InitiatingMessagePresentUERadioCapabilityInfoIndication = 47
const val InitiatingMessagePresentUETNLABindingReleaseRequest = 48
const val InitiatingMessagePresentUplinkNASTransport = 49
const val InitiatingMessagePresentUplinkNonUEAssociatedNRPPaTransport = 50
const val InitiatingMessagePresentUplinkRANConfigurationTransfer = 51
const val InitiatingMessagePresentUplinkRANStatusTransfer = 52
const val InitiatingMessagePresentUplinkUEAssociatedNRPPaTransport = 53

data class InitiatingMessageValue(
    val present: Int,
    val amfConfigurationUpdate: AMFConfigurationUpdate? = null,
    val handoverCancel: HandoverCancel? = null,
    val handoverRequired: HandoverRequired? = null,
    val handoverRequest: HandoverRequest? = null,
    val initialContextSetupRequest: InitialContextSetupRequest? = null,
    val ngReset: NGReset? = null,
    val ngSetupRequest: NGSetupRequest? = null,
    val pathSwitchRequest: PathSwitchRequest? = null,
    val pduSessionResourceModifyRequest: PDUSessionResourceModifyRequest? = null,
    val pduSessionResourceModifyIndication: PDUSessionResourceModifyIndication? = null,
    val pduSessionResourceReleaseCommand: PDUSessionResourceReleaseCommand? = null,
    val pduSessionResourceSetupRequest: PDUSessionResourceSetupRequest? = null,
    val pwsCancelRequest: PWSCancelRequest? = null,
    val ranConfigurationUpdate: RANConfigurationUpdate? = null,
    val ueContextModificationRequest: UEContextModificationRequest? = null,
    val ueContextReleaseCommand: UEContextReleaseCommand? = null,
    val ueRadioCapabilityCheckRequest: UERadioCapabilityCheckRequest? = null,
    val writeReplaceWarningRequest: WriteReplaceWarningRequest? = null,
    val amfStatusIndication: AMFStatusIndication? = null,
    val cellTrafficTrace: CellTrafficTrace? = null,
    val deactivateTrace: DeactivateTrace? = null,
    val downlinkNASTransport: DownlinkNASTransport? = null,
    val downlinkNonUEAssociatedNRPPaTransport: DownlinkNonUEAssociatedNRPPaTransport? = null,
    val downlinkRANConfigurationTransfer: DownlinkRANConfigurationTransfer? = null,
    val downlinkRANStatusTransfer: DownlinkRANStatusTransfer? = null,
    val downlinkUEAssociatedNRPPaTransport: DownlinkUEAssociatedNRPPaTransport? = null,
    val errorIndication: ErrorIndication? = null,
    val handoverNotify: HandoverNotify? = null,
    val initialUEMessage: InitialUEMessage? = null,
    val locationReport: LocationReport? = null,
    val locationReportingControl: LocationReportingControl? = null,
    val locationReportingFailureIndication: LocationReportingFailureIndication? = null,
    val nasNonDeliveryIndication: NASNonDeliveryIndication? = null,
    val overloadStart: OverloadStart? = null,
    val overloadStop: OverloadStop? = null,
    val paging: Paging? = null,
    val pduSessionResourceNotify: PDUSessionResourceNotify? = null,
    val privateMessage: PrivateMessage? = null,
    val pwsFailureIndication: PWSFailureIndication? = null,
    val pwsRestartIndication: PWSRestartIndication? = null,
    val rerouteNASRequest: RerouteNASRequest? = null,
    val rrcInactiveTransitionReport: RRCInactiveTransitionReport? = null,
    val secondaryRATDataUsageReport: SecondaryRATDataUsageReport? = null,
    val traceFailureIndication: TraceFailureIndication? = null,
    val traceStart: TraceStart? = null,
    val ueContextReleaseRequest: UEContextReleaseRequest? = null,
    val ueRadioCapabilityInfoIndication: UERadioCapabilityInfoIndication? = null,
    val ueTNLABindingReleaseRequest: UETNLABindingReleaseRequest? = null,
    val uplinkNASTransport: UplinkNASTransport? = null,
    val uplinkNonUEAssociatedNRPPaTransport: UplinkNonUEAssociatedNRPPaTransport? = null,
    val uplinkRANConfigurationTransfer: UplinkRANConfigurationTransfer? = null,
    val uplinkRANStatusTransfer: UplinkRANStatusTransfer? = null,
    val uplinkUEAssociatedNRPPaTransport: UplinkUEAssociatedNRPPaTransport? = null
)


