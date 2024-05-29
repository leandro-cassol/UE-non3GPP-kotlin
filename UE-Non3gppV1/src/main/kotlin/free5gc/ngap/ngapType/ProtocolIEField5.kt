package free5gc.ngap.ngapType

data class PWSRestartIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PWSRestartIndicationIEsValue
)

enum class PWSRestartIndicationIEsPresent {
    Nothing,
    CellIDListForRestart,
    GlobalRANNodeID,
    TAIListForRestart,
    EmergencyAreaIDListForRestart
}

data class PWSRestartIndicationIEsValue(
    val present: PWSRestartIndicationIEsPresent,
    val cellIDListForRestart: CellIDListForRestart?,
    val globalRANNodeID: GlobalRANNodeID?,
    val taiListForRestart: TAIListForRestart?,
    val emergencyAreaIDListForRestart: EmergencyAreaIDListForRestart?
)

data class PWSFailureIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PWSFailureIndicationIEsValue
)

enum class PWSFailureIndicationIEsPresent {
    Nothing,
    PWSFailedCellIDList,
    GlobalRANNodeID
}

data class PWSFailureIndicationIEsValue(
    val present: PWSFailureIndicationIEsPresent,
    val pwsFailedCellIDList: PWSFailedCellIDList?,
    val globalRANNodeID: GlobalRANNodeID?
)

data class DownlinkUEAssociatedNRPPaTransportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: DownlinkUEAssociatedNRPPaTransportIEsValue
)

enum class DownlinkUEAssociatedNRPPaTransportIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    RoutingID,
    NRPPaPDU
}

data class DownlinkUEAssociatedNRPPaTransportIEsValue(
    val present: DownlinkUEAssociatedNRPPaTransportIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val routingID: RoutingID?,
    val nrpPaPDU: NRPPaPDU?
)

data class UplinkUEAssociatedNRPPaTransportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UplinkUEAssociatedNRPPaTransportIEsValue
)

enum class UplinkUEAssociatedNRPPaTransportIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    RoutingID,
    NRPPaPDU
}

data class UplinkUEAssociatedNRPPaTransportIEsValue(
    val present: UplinkUEAssociatedNRPPaTransportIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val routingID: RoutingID?,
    val nrpPaPDU: NRPPaPDU?
)

data class DownlinkNonUEAssociatedNRPPaTransportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: DownlinkNonUEAssociatedNRPPaTransportIEsValue
)

enum class DownlinkNonUEAssociatedNRPPaTransportIEsPresent {
    Nothing,
    RoutingID,
    NRPPaPDU
}

data class DownlinkNonUEAssociatedNRPPaTransportIEsValue(
    val present: DownlinkNonUEAssociatedNRPPaTransportIEsPresent,
    val routingID: RoutingID?,
    val nrpPaPDU: NRPPaPDU?
)

data class UplinkNonUEAssociatedNRPPaTransportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UplinkNonUEAssociatedNRPPaTransportIEsValue
)

enum class UplinkNonUEAssociatedNRPPaTransportIEsPresent {
    Nothing,
    RoutingID,
    NRPPaPDU
}

data class UplinkNonUEAssociatedNRPPaTransportIEsValue(
    val present: UplinkNonUEAssociatedNRPPaTransportIEsPresent,
    val routingID: RoutingID?,
    val nrpPaPDU: NRPPaPDU?
)

data class TraceStartIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: TraceStartIEsValue
)

enum class TraceStartIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    TraceActivation
}

data class TraceStartIEsValue(
    val present: TraceStartIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val traceActivation: TraceActivation?
)

data class TraceFailureIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: TraceFailureIndicationIEsValue
)

enum class TraceFailureIndicationIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    NGRANTraceID,
    Cause
}

data class TraceFailureIndicationIEsValue(
    val present: TraceFailureIndicationIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val ngranTraceID: NGRANTraceID?,
    val cause: Cause?
)

data class DeactivateTraceIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: DeactivateTraceIEsValue
)

enum class DeactivateTraceIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    NGRANTraceID
}

data class DeactivateTraceIEsValue(
    val present: DeactivateTraceIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val ngranTraceID: NGRANTraceID?
)

data class CellTrafficTraceIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: CellTrafficTraceIEsValue
)

enum class CellTrafficTraceIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    NGRANTraceID,
    NGRANCGI,
    TraceCollectionEntityIPAddress
}

data class CellTrafficTraceIEsValue(
    val present: CellTrafficTraceIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val ngranTraceID: NGRANTraceID?,
    val ngranCGI: NGRANCGI?,
    val traceCollectionEntityIPAddress: TransportLayerAddress?
)

data class LocationReportingControlIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: LocationReportingControlIEsValue
)

enum class LocationReportingControlIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    LocationReportingRequestType
}

data class LocationReportingControlIEsValue(
    val present: LocationReportingControlIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val locationReportingRequestType: LocationReportingRequestType?
)

data class LocationReportingFailureIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: LocationReportingFailureIndicationIEsValue
)

enum class LocationReportingFailureIndicationIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    Cause
}

data class LocationReportingFailureIndicationIEsValue(
    val present: LocationReportingFailureIndicationIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val cause: Cause?
)

data class LocationReportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: LocationReportIEsValue
)

enum class LocationReportIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    UserLocationInformation,
    UEPresenceInAreaOfInterestList,
    LocationReportingRequestType,
    PSCellInformation
}

data class LocationReportIEsValue(
    val present: LocationReportIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val userLocationInformation: UserLocationInformation?,
    val uePresenceInAreaOfInterestList: UEPresenceInAreaOfInterestList?,
    val locationReportingRequestType: LocationReportingRequestType?,
    val psCellInformation: NGRANCGI?
)

data class UETNLABindingReleaseRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UETNLABindingReleaseRequestIEsValue
)

enum class UETNLABindingReleaseRequestIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID
}

data class UETNLABindingReleaseRequestIEsValue(
    val present: UETNLABindingReleaseRequestIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?
)

data class UERadioCapabilityInfoIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UERadioCapabilityInfoIndicationIEsValue
)

enum class UERadioCapabilityInfoIndicationIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    UERadioCapability,
    UERadioCapabilityForPaging
}

data class UERadioCapabilityInfoIndicationIEsValue(
    val present: UERadioCapabilityInfoIndicationIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val ueRadioCapability: UERadioCapability?,
    val ueRadioCapabilityForPaging: UERadioCapabilityForPaging?
)

data class UERadioCapabilityCheckRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UERadioCapabilityCheckRequestIEsValue
)

enum class UERadioCapabilityCheckRequestIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    UERadioCapability
}

data class UERadioCapabilityCheckRequestIEsValue(
    val present: UERadioCapabilityCheckRequestIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val ueRadioCapability: UERadioCapability?
)

data class UERadioCapabilityCheckResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UERadioCapabilityCheckResponseIEsValue
)

enum class UERadioCapabilityCheckResponseIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    IMSVoiceSupportIndicator,
    CriticalityDiagnostics
}

data class UERadioCapabilityCheckResponseIEsValue(
    val present: UERadioCapabilityCheckResponseIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val imsVoiceSupportIndicator: IMSVoiceSupportIndicator?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class SecondaryRATDataUsageReportIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: SecondaryRATDataUsageReportIEsValue
)

enum class SecondaryRATDataUsageReportIEsPresent {
    Nothing,
    AMFUENGAPID,
    RANUENGAPID,
    PDUSessionResourceSecondaryRATUsageList,
    HandoverFlag
}

data class SecondaryRATDataUsageReportIEsValue(
    val present: SecondaryRATDataUsageReportIEsPresent,
    val amfuengapID: AMFUENGAPID?,
    val ranuengapID: RANUENGAPID?,
    val pduSessionResourceSecondaryRATUsageList: PDUSessionResourceSecondaryRATUsageList?,
    val handoverFlag: HandoverFlag?
)

data class PDUSessionResourceModifyRequestTransferIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceModifyRequestTransferIEsValue
)

enum class PDUSessionResourceModifyRequestTransferIEsPresent {
    Nothing,
    PDUSessionAggregateMaximumBitRate,
    ULNGUUPTNLModifyList,
    NetworkInstance,
    QosFlowAddOrModifyRequestList,
    QosFlowToReleaseList,
    AdditionalULNGUUPTNLInformation
}

data class PDUSessionResourceModifyRequestTransferIEsValue(
    val present: PDUSessionResourceModifyRequestTransferIEsPresent,
    val pduSessionAggregateMaximumBitRate: PDUSessionAggregateMaximumBitRate?,
    val ulnguuptnlModifyList: ULNGUUPTNLModifyList?,
    val networkInstance: NetworkInstance?,
    val qosFlowAddOrModifyRequestList: QosFlowAddOrModifyRequestList?,
    val qosFlowToReleaseList: QosFlowListWithCause?,
    val additionalULNGUUPTNLInformation: UPTransportLayerInformationList?
)

data class PDUSessionResourceSetupRequestTransferIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceSetupRequestTransferIEsValue
)

enum class PDUSessionResourceSetupRequestTransferIEsPresent {
    Nothing,
    PDUSessionAggregateMaximumBitRate,
    ULNGUUPTNLInformation,
    AdditionalULNGUUPTNLInformation,
    DataForwardingNotPossible,
    PDUSessionType,
    SecurityIndication,
    NetworkInstance,
    QosFlowSetupRequestList
}

data class PDUSessionResourceSetupRequestTransferIEsValue(
    val present: PDUSessionResourceSetupRequestTransferIEsPresent,
    val pduSessionAggregateMaximumBitRate: PDUSessionAggregateMaximumBitRate?,
    val ulnguuptnlInformation: UPTransportLayerInformation?,
    val additionalULNGUUPTNLInformation: UPTransportLayerInformationList?,
    val dataForwardingNotPossible: DataForwardingNotPossible?,
    val pduSessionType: PDUSessionType?,
    val securityIndication: SecurityIndication?,
    val networkInstance: NetworkInstance?,
    val qosFlowSetupRequestList: QosFlowSetupRequestList?
)


