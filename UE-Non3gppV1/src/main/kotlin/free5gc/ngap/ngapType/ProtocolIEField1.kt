package free5gc.ngap.ngapType

data class AMFPagingTargetExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: AMFPagingTargetExtIEsValue
)

data class AMFPagingTargetExtIEsValue(
    val present: Int
)

const val AMFPagingTargetExtIEsPresentNothing = 0

data class BroadcastCancelledAreaListExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: BroadcastCancelledAreaListExtIEsValue
)

data class BroadcastCancelledAreaListExtIEsValue(
    val present: Int
)

const val BroadcastCancelledAreaListExtIEsPresentNothing = 0

data class BroadcastCompletedAreaListExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: BroadcastCompletedAreaListExtIEsValue
)

data class BroadcastCompletedAreaListExtIEsValue(
    val present: Int
)

const val BroadcastCompletedAreaListExtIEsPresentNothing = 0

data class CauseExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: CauseExtIEsValue
)

data class CauseExtIEsValue(
    val present: Int
)

const val CauseExtIEsPresentNothing = 0

data class CellIDListForRestartExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: CellIDListForRestartExtIEsValue
)

data class CellIDListForRestartExtIEsValue(
    val present: Int
)

const val CellIDListForRestartExtIEsPresentNothing = 0

data class CPTransportLayerInformationExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: CPTransportLayerInformationExtIEsValue
)

data class CPTransportLayerInformationExtIEsValue(
    val present: Int
)

const val CPTransportLayerInformationExtIEsPresentNothing = 0

data class DRBStatusDLExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: DRBStatusDLExtIEsValue
)

data class DRBStatusDLExtIEsValue(
    val present: Int
)

const val DRBStatusDLExtIEsPresentNothing = 0

data class DRBStatusULExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: DRBStatusULExtIEsValue
)

data class DRBStatusULExtIEsValue(
    val present: Int
)

const val DRBStatusULExtIEsPresentNothing = 0

data class GlobalRANNodeIDExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: GlobalRANNodeIDExtIEsValue
)

data class GlobalRANNodeIDExtIEsValue(
    val present: Int
)

const val GlobalRANNodeIDExtIEsPresentNothing = 0

data class GNBIDExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: GNBIDExtIEsValue
)

data class GNBIDExtIEsValue(
    val present: Int
)

const val GNBIDExtIEsPresentNothing = 0

data class LastVisitedCellInformationExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: LastVisitedCellInformationExtIEsValue
)

data class LastVisitedCellInformationExtIEsValue(
    val present: Int
)

const val LastVisitedCellInformationExtIEsPresentNothing = 0

data class N3IWFIDExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: N3IWFIDExtIEsValue
)

data class N3IWFIDExtIEsValue(
    val present: Int
)

const val N3IWFIDExtIEsPresentNothing = 0

data class NgENBIDExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: NgENBIDExtIEsValue
)

data class NgENBIDExtIEsValue(
    val present: Int
)

const val NgENBIDExtIEsPresentNothing = 0

data class NGRANCGIExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: NGRANCGIExtIEsValue
)

data class NGRANCGIExtIEsValue(
    val present: Int
)

const val NGRANCGIExtIEsPresentNothing = 0

data class OverloadResponseExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: OverloadResponseExtIEsValue
)

data class OverloadResponseExtIEsValue(
    val present: Int
)

const val OverloadResponseExtIEsPresentNothing = 0

data class PWSFailedCellIDListExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PWSFailedCellIDListExtIEsValue
)

data class PWSFailedCellIDListExtIEsValue(
    val present: Int
)

const val PWSFailedCellIDListExtIEsPresentNothing = 0

data class QosCharacteristicsExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: QosCharacteristicsExtIEsValue
)

data class QosCharacteristicsExtIEsValue(
    val present: Int
)

const val QosCharacteristicsExtIEsPresentNothing = 0

data class ResetTypeExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: ResetTypeExtIEsValue
)

data class ResetTypeExtIEsValue(
    val present: Int
)

const val ResetTypeExtIEsPresentNothing = 0

data class SONInformationExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: SONInformationExtIEsValue
)

data class SONInformationExtIEsValue(
    val present: Int
)

const val SONInformationExtIEsPresentNothing = 0

data class TargetIDExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: TargetIDExtIEsValue
)

data class TargetIDExtIEsValue(
    val present: Int
)

const val TargetIDExtIEsPresentNothing = 0

data class UEIdentityIndexValueExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UEIdentityIndexValueExtIEsValue
)

data class UEIdentityIndexValueExtIEsValue(
    val present: Int
)

const val UEIdentityIndexValueExtIEsPresentNothing = 0

data class UENGAPIDsExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UENGAPIDsExtIEsValue
)

data class UENGAPIDsExtIEsValue(
    val present: Int
)

const val UENGAPIDsExtIEsPresentNothing = 0

data class UEPagingIdentityExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UEPagingIdentityExtIEsValue
)

data class UEPagingIdentityExtIEsValue(
    val present: Int
)

const val UEPagingIdentityExtIEsPresentNothing = 0

data class UPTransportLayerInformationExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UPTransportLayerInformationExtIEsValue
)

data class UPTransportLayerInformationExtIEsValue(
    val present: Int
)

const val UPTransportLayerInformationExtIEsPresentNothing = 0

data class UserLocationInformationExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: UserLocationInformationExtIEsValue
)

data class UserLocationInformationExtIEsValue(
    val present: Int
)

const val UserLocationInformationExtIEsPresentNothing = 0

data class WarningAreaListExtIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: WarningAreaListExtIEsValue
)

data class WarningAreaListExtIEsValue(
    val present: Int
)

const val WarningAreaListExtIEsPresentNothing = 0

data class PDUSessionResourceSetupRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceSetupRequestIEsValue
)

data class PDUSessionResourceSetupRequestIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val ranPagingPriority: RANPagingPriority?,
    val nasPdu: NASPDU?,
    val pduSessionResourceSetupListSUReq: PDUSessionResourceSetupListSUReq?,
    val ueAggregateMaximumBitRate: UEAggregateMaximumBitRate?
)

data class PDUSessionResourceSetupResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceSetupResponseIEsValue
)

data class PDUSessionResourceSetupResponseIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val pduSessionResourceSetupListSURes: PDUSessionResourceSetupListSURes?,
    val pduSessionResourceFailedToSetupListSURes: PDUSessionResourceFailedToSetupListSURes?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class PDUSessionResourceReleaseCommandIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceReleaseCommandIEsValue
)

data class PDUSessionResourceReleaseCommandIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val ranPagingPriority: RANPagingPriority?,
    val nasPdu: NASPDU?,
    val pduSessionResourceToReleaseListRelCmd: PDUSessionResourceToReleaseListRelCmd?
)

data class PDUSessionResourceReleaseResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceReleaseResponseIEsValue
)

data class PDUSessionResourceReleaseResponseIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val pduSessionResourceReleasedListRelRes: PDUSessionResourceReleasedListRelRes?,
    val userLocationInformation: UserLocationInformation?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class PDUSessionResourceModifyRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceModifyRequestIEsValue
)

data class PDUSessionResourceModifyRequestIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val ranPagingPriority: RANPagingPriority?,
    val pduSessionResourceModifyListModReq: PDUSessionResourceModifyListModReq?
)

data class PDUSessionResourceModifyResponseIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceModifyResponseIEsValue
)

data class PDUSessionResourceModifyResponseIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val pduSessionResourceModifyListModRes: PDUSessionResourceModifyListModRes?,
    val pduSessionResourceFailedToModifyListModRes: PDUSessionResourceFailedToModifyListModRes?,
    val userLocationInformation: UserLocationInformation?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class PDUSessionResourceNotifyIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceNotifyIEsValue
)

data class PDUSessionResourceNotifyIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val pduSessionResourceNotifyList: PDUSessionResourceNotifyList?,
    val pduSessionResourceReleasedListNot: PDUSessionResourceReleasedListNot?,
    val userLocationInformation: UserLocationInformation?
)

data class PDUSessionResourceModifyIndicationIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceModifyIndicationIEsValue
)

data class PDUSessionResourceModifyIndicationIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val pduSessionResourceModifyListModInd: PDUSessionResourceModifyListModInd?
)

data class PDUSessionResourceModifyConfirmIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: PDUSessionResourceModifyConfirmIEsValue
)

data class PDUSessionResourceModifyConfirmIEsValue(
    val present: Int,
    val amfUeNgapId: AMFUENGAPID?,
    val ranUeNgapId: RANUENGAPID?,
    val pduSessionResourceModifyListModCfm: PDUSessionResourceModifyListModCfm?,
    val pduSessionResourceFailedToModifyListModCfm: PDUSessionResourceFailedToModifyListModCfm?,
    val criticalityDiagnostics: CriticalityDiagnostics?
)

data class InitialContextSetupRequestIEs(
    val id: ProtocolIEID,
    val criticality: Criticality,
    val value: InitialContextSetupRequestIEsValue
)


