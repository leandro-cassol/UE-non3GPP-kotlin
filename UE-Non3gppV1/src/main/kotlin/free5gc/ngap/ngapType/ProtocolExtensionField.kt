package free5gc.ngap.ngapType

import org.example.free5gc.ngap.ngapType.ProtocolExtensionID

data class AdditionalDLUPTNLInformationForHOItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AdditionalDLUPTNLInformationForHOItemExtIEsExtensionValue
)

const val AdditionalDLUPTNLInformationForHOItemExtIEsPresentNothing = 0

data class AdditionalDLUPTNLInformationForHOItemExtIEsExtensionValue(
    val present: Int
)

data class AllocationAndRetentionPriorityExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AllocationAndRetentionPriorityExtIEsExtensionValue
)

const val AllocationAndRetentionPriorityExtIEsPresentNothing = 0

data class AllocationAndRetentionPriorityExtIEsExtensionValue(
    val present: Int
)

data class AllowedNSSAIItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AllowedNSSAIItemExtIEsExtensionValue
)

const val AllowedNSSAIItemExtIEsPresentNothing = 0

data class AllowedNSSAIItemExtIEsExtensionValue(
    val present: Int
)

data class AMFTNLAssociationSetupItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AMFTNLAssociationSetupItemExtIEsExtensionValue
)

const val AMFTNLAssociationSetupItemExtIEsPresentNothing = 0

data class AMFTNLAssociationSetupItemExtIEsExtensionValue(
    val present: Int
)

data class AMFTNLAssociationToAddItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AMFTNLAssociationToAddItemExtIEsExtensionValue
)

const val AMFTNLAssociationToAddItemExtIEsPresentNothing = 0

data class AMFTNLAssociationToAddItemExtIEsExtensionValue(
    val present: Int
)

data class AMFTNLAssociationToRemoveItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AMFTNLAssociationToRemoveItemExtIEsExtensionValue
)

const val AMFTNLAssociationToRemoveItemExtIEsPresentNothing = 0

data class AMFTNLAssociationToRemoveItemExtIEsExtensionValue(
    val present: Int
)

data class AMFTNLAssociationToUpdateItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AMFTNLAssociationToUpdateItemExtIEsExtensionValue
)

const val AMFTNLAssociationToUpdateItemExtIEsPresentNothing = 0

data class AMFTNLAssociationToUpdateItemExtIEsExtensionValue(
    val present: Int
)

data class AreaOfInterestExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AreaOfInterestExtIEsExtensionValue
)

const val AreaOfInterestExtIEsPresentNothing = 0

data class AreaOfInterestExtIEsExtensionValue(
    val present: Int
)

data class AreaOfInterestCellItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AreaOfInterestCellItemExtIEsExtensionValue
)

const val AreaOfInterestCellItemExtIEsPresentNothing = 0

data class AreaOfInterestCellItemExtIEsExtensionValue(
    val present: Int
)

data class AreaOfInterestItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AreaOfInterestItemExtIEsExtensionValue
)

const val AreaOfInterestItemExtIEsPresentNothing = 0

data class AreaOfInterestItemExtIEsExtensionValue(
    val present: Int
)

data class AreaOfInterestRANNodeItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AreaOfInterestRANNodeItemExtIEsExtensionValue
)

const val AreaOfInterestRANNodeItemExtIEsPresentNothing = 0

data class AreaOfInterestRANNodeItemExtIEsExtensionValue(
    val present: Int
)

data class AreaOfInterestTAIItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AreaOfInterestTAIItemExtIEsExtensionValue
)

const val AreaOfInterestTAIItemExtIEsPresentNothing = 0

data class AreaOfInterestTAIItemExtIEsExtensionValue(
    val present: Int
)

data class AssistanceDataForPagingExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AssistanceDataForPagingExtIEsExtensionValue
)

const val AssistanceDataForPagingExtIEsPresentNothing = 0

data class AssistanceDataForPagingExtIEsExtensionValue(
    val present: Int
)

data class AssistanceDataForRecommendedCellsExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AssistanceDataForRecommendedCellsExtIEsExtensionValue
)

const val AssistanceDataForRecommendedCellsExtIEsPresentNothing = 0

data class AssistanceDataForRecommendedCellsExtIEsExtensionValue(
    val present: Int
)

data class AssociatedQosFlowItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: AssociatedQosFlowItemExtIEsExtensionValue
)

const val AssociatedQosFlowItemExtIEsPresentNothing = 0

data class AssociatedQosFlowItemExtIEsExtensionValue(
    val present: Int
)

data class BroadcastPLMNItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: BroadcastPLMNItemExtIEsExtensionValue
)

const val BroadcastPLMNItemExtIEsPresentNothing = 0

data class BroadcastPLMNItemExtIEsExtensionValue(
    val present: Int
)

data class CancelledCellsInEAIEUTRAItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CancelledCellsInEAIEUTRAItemExtIEsExtensionValue
)

const val CancelledCellsInEAIEUTRAItemExtIEsPresentNothing = 0

data class CancelledCellsInEAIEUTRAItemExtIEsExtensionValue(
    val present: Int
)

data class CancelledCellsInEAINRItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CancelledCellsInEAINRItemExtIEsExtensionValue
)

const val CancelledCellsInEAINRItemExtIEsPresentNothing = 0

data class CancelledCellsInEAINRItemExtIEsExtensionValue(
    val present: Int
)

data class CancelledCellsInTAIEUTRAItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CancelledCellsInTAIEUTRAItemExtIEsExtensionValue
)

const val CancelledCellsInTAIEUTRAItemExtIEsPresentNothing = 0

data class CancelledCellsInTAIEUTRAItemExtIEsExtensionValue(
    val present: Int
)

data class CancelledCellsInTAINRItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CancelledCellsInTAINRItemExtIEsExtensionValue
)

const val CancelledCellsInTAINRItemExtIEsPresentNothing = 0

data class CancelledCellsInTAINRItemExtIEsExtensionValue(
    val present: Int
)

data class CellIDBroadcastEUTRAItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CellIDBroadcastEUTRAItemExtIEsExtensionValue
)

const val CellIDBroadcastEUTRAItemExtIEsPresentNothing = 0

data class CellIDBroadcastEUTRAItemExtIEsExtensionValue(
    val present: Int
)

data class CellIDBroadcastNRItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CellIDBroadcastNRItemExtIEsExtensionValue
)

const val CellIDBroadcastNRItemExtIEsPresentNothing = 0

data class CellIDBroadcastNRItemExtIEsExtensionValue(
    val present: Int
)

data class CellIDCancelledEUTRAItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CellIDCancelledEUTRAItemExtIEsExtensionValue
)

const val CellIDCancelledEUTRAItemExtIEsPresentNothing = 0

data class CellIDCancelledEUTRAItemExtIEsExtensionValue(
    val present: Int
)

data class CellIDCancelledNRItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CellIDCancelledNRItemExtIEsExtensionValue
)

const val CellIDCancelledNRItemExtIEsPresentNothing = 0

data class CellIDCancelledNRItemExtIEsExtensionValue(
    val present: Int
)

data class CellTypeExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CellTypeExtIEsExtensionValue
)

const val CellTypeExtIEsPresentNothing = 0

data class CellTypeExtIEsExtensionValue(
    val present: Int
)

data class CompletedCellsInEAIEUTRAItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CompletedCellsInEAIEUTRAItemExtIEsExtensionValue
)

const val CompletedCellsInEAIEUTRAItemExtIEsPresentNothing = 0

data class CompletedCellsInEAIEUTRAItemExtIEsExtensionValue(
    val present: Int
)

data class CompletedCellsInEAINRItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CompletedCellsInEAINRItemExtIEsExtensionValue
)

const val CompletedCellsInEAINRItemExtIEsPresentNothing = 0

data class CompletedCellsInEAINRItemExtIEsExtensionValue(
    val present: Int
)

data class CompletedCellsInTAIEUTRAItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CompletedCellsInTAIEUTRAItemExtIEsExtensionValue
)

const val CompletedCellsInTAIEUTRAItemExtIEsPresentNothing = 0

data class CompletedCellsInTAIEUTRAItemExtIEsExtensionValue(
    val present: Int
)

data class CompletedCellsInTAINRItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CompletedCellsInTAINRItemExtIEsExtensionValue
)

const val CompletedCellsInTAINRItemExtIEsPresentNothing = 0

data class CompletedCellsInTAINRItemExtIEsExtensionValue(
    val present: Int
)

data class CoreNetworkAssistanceInformationExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CoreNetworkAssistanceInformationExtIEsExtensionValue
)

const val CoreNetworkAssistanceInformationExtIEsPresentNothing = 0

data class CoreNetworkAssistanceInformationExtIEsExtensionValue(
    val present: Int
)

data class COUNTValueForPDCPSN12ExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: COUNTValueForPDCPSN12ExtIEsExtensionValue
)

const val COUNTValueForPDCPSN12ExtIEsPresentNothing = 0

data class COUNTValueForPDCPSN12ExtIEsExtensionValue(
    val present: Int
)

data class COUNTValueForPDCPSN18ExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: COUNTValueForPDCPSN18ExtIEsExtensionValue
)

const val COUNTValueForPDCPSN18ExtIEsPresentNothing = 0

data class COUNTValueForPDCPSN18ExtIEsExtensionValue(
    val present: Int
)

data class CriticalityDiagnosticsExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CriticalityDiagnosticsExtIEsExtensionValue
)

const val CriticalityDiagnosticsExtIEsPresentNothing = 0

data class CriticalityDiagnosticsExtIEsExtensionValue(
    val present: Int
)

data class CriticalityDiagnosticsIEItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: CriticalityDiagnosticsIEItemExtIEsExtensionValue
)

const val CriticalityDiagnosticsIEItemExtIEsPresentNothing = 0

data class CriticalityDiagnosticsIEItemExtIEsExtensionValue(
    val present: Int
)

data class DataForwardingResponseDRBItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: DataForwardingResponseDRBItemExtIEsExtensionValue
)

const val DataForwardingResponseDRBItemExtIEsPresentNothing = 0

data class DataForwardingResponseDRBItemExtIEsExtensionValue(
    val present: Int
)

data class DRBsSubjectToStatusTransferItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: DRBsSubjectToStatusTransferItemExtIEsExtensionValue
)

const val DRBsSubjectToStatusTransferItemExtIEsPresentNothing = 0

data class DRBsSubjectToStatusTransferItemExtIEsExtensionValue(
    val present: Int
)

data class DRBStatusDL12ExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: DRBStatusDL12ExtIEsExtensionValue
)

const val DRBStatusDL12ExtIEsPresentNothing = 0

data class DRBStatusDL12ExtIEsExtensionValue(
    val present: Int
)

data class DRBStatusDL18ExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: DRBStatusDL18ExtIEsExtensionValue
)

const val DRBStatusDL18ExtIEsPresentNothing = 0

data class DRBStatusDL18ExtIEsExtensionValue(
    val present: Int
)

data class DRBStatusUL12ExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: DRBStatusUL12ExtIEsExtensionValue
)

const val DRBStatusUL12ExtIEsPresentNothing = 0

data class DRBStatusUL12ExtIEsExtensionValue(
    val present: Int
)

data class DRBStatusUL18ExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: DRBStatusUL18ExtIEsExtensionValue
)

const val DRBStatusUL18ExtIEsPresentNothing = 0

data class DRBStatusUL18ExtIEsExtensionValue(
    val present: Int
)

data class DRBsToQosFlowsMappingItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: DRBsToQosFlowsMappingItemExtIEsExtensionValue
)

const val DRBsToQosFlowsMappingItemExtIEsPresentNothing = 0

data class DRBsToQosFlowsMappingItemExtIEsExtensionValue(
    val present: Int
)

data class Dynamic5QIDescriptorExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: Dynamic5QIDescriptorExtIEsExtensionValue
)

const val Dynamic5QIDescriptorExtIEsPresentNothing = 0

data class Dynamic5QIDescriptorExtIEsExtensionValue(
    val present: Int
)

data class EmergencyAreaIDBroadcastEUTRAItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: EmergencyAreaIDBroadcastEUTRAItemExtIEsExtensionValue
)

const val EmergencyAreaIDBroadcastEUTRAItemExtIEsPresentNothing = 0

data class EmergencyAreaIDBroadcastEUTRAItemExtIEsExtensionValue(
    val present: Int
)

data class EmergencyAreaIDBroadcastNRItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: EmergencyAreaIDBroadcastNRItemExtIEsExtensionValue
)

const val EmergencyAreaIDBroadcastNRItemExtIEsPresentNothing = 0

data class EmergencyAreaIDBroadcastNRItemExtIEsExtensionValue(
    val present: Int
)

data class EmergencyAreaIDCancelledEUTRAItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: EmergencyAreaIDCancelledEUTRAItemExtIEsExtensionValue
)

const val EmergencyAreaIDCancelledEUTRAItemExtIEsPresentNothing = 0

data class EmergencyAreaIDCancelledEUTRAItemExtIEsExtensionValue(
    val present: Int
)

data class EmergencyAreaIDCancelledNRItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: EmergencyAreaIDCancelledNRItemExtIEsExtensionValue
)

const val EmergencyAreaIDCancelledNRItemExtIEsPresentNothing = 0

data class EmergencyAreaIDCancelledNRItemExtIEsExtensionValue(
    val present: Int
)

data class EmergencyFallbackIndicatorExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: EmergencyFallbackIndicatorExtIEsExtensionValue
)

const val EmergencyFallbackIndicatorExtIEsPresentNothing = 0

data class EmergencyFallbackIndicatorExtIEsExtensionValue(
    val present: Int
)

data class EPSTAIExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: EPSTAIExtIEsExtensionValue
)

const val EPSTAIExtIEsPresentNothing = 0

data class EPSTAIExtIEsExtensionValue(
    val present: Int
)

data class ERABInformationItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: ERABInformationItemExtIEsExtensionValue
)

const val ERABInformationItemExtIEsPresentNothing = 0

data class ERABInformationItemExtIEsExtensionValue(
    val present: Int
)

data class EUTRACGIExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: EUTRACGIExtIEsExtensionValue
)

const val EUTRACGIExtIEsPresentNothing = 0

data class EUTRACGIExtIEsExtensionValue(
    val present: Int
)

data class ExpectedUEActivityBehaviourExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: ExpectedUEActivityBehaviourExtIEsExtensionValue
)

const val ExpectedUEActivityBehaviourExtIEsPresentNothing = 0

data class ExpectedUEActivityBehaviourExtIEsExtensionValue(
    val present: Int
)

data class ExpectedUEBehaviourExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: ExpectedUEBehaviourExtIEsExtensionValue
)

const val ExpectedUEBehaviourExtIEsPresentNothing = 0

data class ExpectedUEBehaviourExtIEsExtensionValue(
    val present: Int
)


data class ExpectedUEMovingTrajectoryItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: ExpectedUEMovingTrajectoryItemExtIEsExtensionValue
)

const val ExpectedUEMovingTrajectoryItemExtIEsPresentNothing = 0

data class ExpectedUEMovingTrajectoryItemExtIEsExtensionValue(
    val present: Int
)

data class FiveGSTMSIExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: FiveGSTMSIExtIEsExtensionValue
)

const val FiveGSTMSIExtIEsPresentNothing = 0

data class FiveGSTMSIExtIEsExtensionValue(
    val present: Int
)

data class ForbiddenAreaInformationItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: ForbiddenAreaInformationItemExtIEsExtensionValue
)

const val ForbiddenAreaInformationItemExtIEsPresentNothing = 0

data class ForbiddenAreaInformationItemExtIEsExtensionValue(
    val present: Int
)

data class GBRQosInformationExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: GBRQosInformationExtIEsExtensionValue
)

const val GBRQosInformationExtIEsPresentNothing = 0

data class GBRQosInformationExtIEsExtensionValue(
    val present: Int
)

data class GlobalGNBIDExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: GlobalGNBIDExtIEsExtensionValue
)

const val GlobalGNBIDExtIEsPresentNothing = 0

data class GlobalGNBIDExtIEsExtensionValue(
    val present: Int
)

data class GlobalN3IWFIDExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: GlobalN3IWFIDExtIEsExtensionValue
)

const val GlobalN3IWFIDExtIEsPresentNothing = 0

data class GlobalN3IWFIDExtIEsExtensionValue(
    val present: Int
)

data class GlobalNgENBIDExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: GlobalNgENBIDExtIEsExtensionValue
)

const val GlobalNgENBIDExtIEsPresentNothing = 0

data class GlobalNgENBIDExtIEsExtensionValue(
    val present: Int
)

data class GTPTunnelExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: GTPTunnelExtIEsExtensionValue
)

const val GTPTunnelExtIEsPresentNothing = 0

data class GTPTunnelExtIEsExtensionValue(
    val present: Int
)

data class GUAMIExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: GUAMIExtIEsExtensionValue
)

const val GUAMIExtIEsPresentNothing = 0

data class GUAMIExtIEsExtensionValue(
    val present: Int
)

data class HandoverCommandTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: HandoverCommandTransferExtIEsExtensionValue
)

const val HandoverCommandTransferExtIEsPresentNothing = 0
const val HandoverCommandTransferExtIEsPresentAdditionalDLForwardingUPTNLInformation = 1

data class HandoverCommandTransferExtIEsExtensionValue(
    val present: Int,
    val additionalDLForwardingUPTNLInformation: QosFlowPerTNLInformationList?
)

data class HandoverPreparationUnsuccessfulTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: HandoverPreparationUnsuccessfulTransferExtIEsExtensionValue
)

const val HandoverPreparationUnsuccessfulTransferExtIEsPresentNothing = 0

data class HandoverPreparationUnsuccessfulTransferExtIEsExtensionValue(
    val present: Int
)

data class HandoverRequestAcknowledgeTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: HandoverRequestAcknowledgeTransferExtIEsExtensionValue
)

const val HandoverRequestAcknowledgeTransferExtIEsPresentNothing = 0
const val HandoverRequestAcknowledgeTransferExtIEsPresentAdditionalDLUPTNLInformationForHOList = 1

data class HandoverRequestAcknowledgeTransferExtIEsExtensionValue(
    val present: Int,
    val additionalDLUPTNLInformationForHOList: AdditionalDLUPTNLInformationForHOList?
)

data class HandoverRequiredTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: HandoverRequiredTransferExtIEsExtensionValue
)

const val HandoverRequiredTransferExtIEsPresentNothing = 0

data class HandoverRequiredTransferExtIEsExtensionValue(
    val present: Int
)

data class HandoverResourceAllocationUnsuccessfulTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: HandoverResourceAllocationUnsuccessfulTransferExtIEsExtensionValue
)

const val HandoverResourceAllocationUnsuccessfulTransferExtIEsPresentNothing = 0

data class HandoverResourceAllocationUnsuccessfulTransferExtIEsExtensionValue(
    val present: Int
)

data class InfoOnRecommendedCellsAndRANNodesForPagingExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: InfoOnRecommendedCellsAndRANNodesForPagingExtIEsExtensionValue
)

const val InfoOnRecommendedCellsAndRANNodesForPagingExtIEsPresentNothing = 0

data class InfoOnRecommendedCellsAndRANNodesForPagingExtIEsExtensionValue(
    val present: Int
)

data class LastVisitedCellItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: LastVisitedCellItemExtIEsExtensionValue
)

const val LastVisitedCellItemExtIEsPresentNothing = 0

data class LastVisitedCellItemExtIEsExtensionValue(
    val present: Int
)

data class LastVisitedNGRANCellInformationExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: LastVisitedNGRANCellInformationExtIEsExtensionValue
)

const val LastVisitedNGRANCellInformationExtIEsPresentNothing = 0

data class LastVisitedNGRANCellInformationExtIEsExtensionValue(
    val present: Int
)

data class LocationReportingRequestTypeExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: LocationReportingRequestTypeExtIEsExtensionValue
)

const val LocationReportingRequestTypeExtIEsPresentNothing = 0

data class LocationReportingRequestTypeExtIEsExtensionValue(
    val present: Int
)

data class MobilityRestrictionListExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: MobilityRestrictionListExtIEsExtensionValue
)

const val MobilityRestrictionListExtIEsPresentNothing = 0
const val MobilityRestrictionListExtIEsPresentLastEUTRANPLMNIdentity = 1

data class MobilityRestrictionListExtIEsExtensionValue(
    val present: Int,
    val lastEUTRANPLMNIdentity: PLMNIdentity?
)

data class NonDynamic5QIDescriptorExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: NonDynamic5QIDescriptorExtIEsExtensionValue
)

const val NonDynamic5QIDescriptorExtIEsPresentNothing = 0

data class NonDynamic5QIDescriptorExtIEsExtensionValue(
    val present: Int
)

data class NRCGIExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: NRCGIExtIEsExtensionValue
)

const val NRCGIExtIEsPresentNothing = 0

data class NRCGIExtIEsExtensionValue(
    val present: Int
)

data class OverloadStartNSSAIItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: OverloadStartNSSAIItemExtIEsExtensionValue
)

const val OverloadStartNSSAIItemExtIEsPresentNothing = 0

data class OverloadStartNSSAIItemExtIEsExtensionValue(
    val present: Int
)

data class PacketErrorRateExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PacketErrorRateExtIEsExtensionValue
)

const val PacketErrorRateExtIEsPresentNothing = 0

data class PacketErrorRateExtIEsExtensionValue(
    val present: Int
)

data class PagingAttemptInformationExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PagingAttemptInformationExtIEsExtensionValue
)

const val PagingAttemptInformationExtIEsPresentNothing = 0

data class PagingAttemptInformationExtIEsExtensionValue(
    val present: Int
)

data class PathSwitchRequestAcknowledgeTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PathSwitchRequestAcknowledgeTransferExtIEsExtensionValue
)

const val PathSwitchRequestAcknowledgeTransferExtIEsPresentNothing = 0
const val PathSwitchRequestAcknowledgeTransferExtIEsPresentAdditionalNGUUPTNLInformation = 1

data class PathSwitchRequestAcknowledgeTransferExtIEsExtensionValue(
    val present: Int,
    val additionalNGUUPTNLInformation: UPTransportLayerInformationPairList?
)

data class PathSwitchRequestSetupFailedTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PathSwitchRequestSetupFailedTransferExtIEsExtensionValue
)

const val PathSwitchRequestSetupFailedTransferExtIEsPresentNothing = 0

data class PathSwitchRequestSetupFailedTransferExtIEsExtensionValue(
    val present: Int
)

data class PathSwitchRequestTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PathSwitchRequestTransferExtIEsExtensionValue
)

const val PathSwitchRequestTransferExtIEsPresentNothing = 0
const val PathSwitchRequestTransferExtIEsPresentAdditionalDLQosFlowPerTNLInformation = 1

data class PathSwitchRequestTransferExtIEsExtensionValue(
    val present: Int,
    val additionalDLQosFlowPerTNLInformation: QosFlowPerTNLInformationList?
)

data class PathSwitchRequestUnsuccessfulTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PathSwitchRequestUnsuccessfulTransferExtIEsExtensionValue
)

const val PathSwitchRequestUnsuccessfulTransferExtIEsPresentNothing = 0

data class PathSwitchRequestUnsuccessfulTransferExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionAggregateMaximumBitRateExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionAggregateMaximumBitRateExtIEsExtensionValue
)

const val PDUSessionAggregateMaximumBitRateExtIEsPresentNothing = 0

data class PDUSessionAggregateMaximumBitRateExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceAdmittedItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceAdmittedItemExtIEsExtensionValue
)

const val PDUSessionResourceAdmittedItemExtIEsPresentNothing = 0

data class PDUSessionResourceAdmittedItemExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceFailedToModifyItemModCfmExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceFailedToModifyItemModCfmExtIEsExtensionValue
)

const val PDUSessionResourceFailedToModifyItemModCfmExtIEsPresentNothing = 0

data class PDUSessionResourceFailedToModifyItemModCfmExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceFailedToModifyItemModResExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceFailedToModifyItemModResExtIEsExtensionValue
)

const val PDUSessionResourceFailedToModifyItemModResExtIEsPresentNothing = 0

data class PDUSessionResourceFailedToModifyItemModResExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceFailedToSetupItemCxtFailExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceFailedToSetupItemCxtFailExtIEsExtensionValue
)

const val PDUSessionResourceFailedToSetupItemCxtFailExtIEsPresentNothing = 0

data class PDUSessionResourceFailedToSetupItemCxtFailExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceFailedToSetupItemCxtResExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceFailedToSetupItemCxtResExtIEsExtensionValue
)

const val PDUSessionResourceFailedToSetupItemCxtResExtIEsPresentNothing = 0

data class PDUSessionResourceFailedToSetupItemCxtResExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceFailedToSetupItemHOAckExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceFailedToSetupItemHOAckExtIEsExtensionValue
)

const val PDUSessionResourceFailedToSetupItemHOAckExtIEsPresentNothing = 0

data class PDUSessionResourceFailedToSetupItemHOAckExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceFailedToSetupItemPSReqExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceFailedToSetupItemPSReqExtIEsExtensionValue
)

const val PDUSessionResourceFailedToSetupItemPSReqExtIEsPresentNothing = 0

data class PDUSessionResourceFailedToSetupItemPSReqExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceFailedToSetupItemSUResExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceFailedToSetupItemSUResExtIEsExtensionValue
)

const val PDUSessionResourceFailedToSetupItemSUResExtIEsPresentNothing = 0

data class PDUSessionResourceFailedToSetupItemSUResExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceHandoverItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceHandoverItemExtIEsExtensionValue
)

const val PDUSessionResourceHandoverItemExtIEsPresentNothing = 0

data class PDUSessionResourceHandoverItemExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceInformationItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceInformationItemExtIEsExtensionValue
)

const val PDUSessionResourceInformationItemExtIEsPresentNothing = 0

data class PDUSessionResourceInformationItemExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceItemCxtRelCplExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceItemCxtRelCplExtIEsExtensionValue
)

const val PDUSessionResourceItemCxtRelCplExtIEsPresentNothing = 0
const val PDUSessionResourceItemCxtRelCplExtIEsPresentPDUSessionResourceReleaseResponseTransfer = 1

data class PDUSessionResourceItemCxtRelCplExtIEsExtensionValue(
    val present: Int,
    val pDUSessionResourceReleaseResponseTransfer: ByteArray?
)

data class PDUSessionResourceItemCxtRelReqExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceItemCxtRelReqExtIEsExtensionValue
)

const val PDUSessionResourceItemCxtRelReqExtIEsPresentNothing = 0

data class PDUSessionResourceItemCxtRelReqExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceItemHORqdExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceItemHORqdExtIEsExtensionValue
)

const val PDUSessionResourceItemHORqdExtIEsPresentNothing = 0

data class PDUSessionResourceItemHORqdExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceModifyConfirmTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyConfirmTransferExtIEsExtensionValue
)

const val PDUSessionResourceModifyConfirmTransferExtIEsPresentNothing = 0

data class PDUSessionResourceModifyConfirmTransferExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceModifyIndicationUnsuccessfulTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyIndicationUnsuccessfulTransferExtIEsExtensionValue
)

const val PDUSessionResourceModifyIndicationUnsuccessfulTransferExtIEsPresentNothing = 0

data class PDUSessionResourceModifyIndicationUnsuccessfulTransferExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceModifyResponseTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyResponseTransferExtIEsExtensionValue
)

const val PDUSessionResourceModifyResponseTransferExtIEsPresentNothing = 0
const val PDUSessionResourceModifyResponseTransferExtIEsPresentAdditionalNGUUPTNLInformation = 1

data class PDUSessionResourceModifyResponseTransferExtIEsExtensionValue(
    val present: Int,
    val additionalNGUUPTNLInformation: UPTransportLayerInformationPairList?
)

data class PDUSessionResourceModifyIndicationTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyIndicationTransferExtIEsExtensionValue
)

const val PDUSessionResourceModifyIndicationTransferExtIEsPresentNothing = 0
const val PDUSessionResourceModifyIndicationTransferExtIEsPresentSecondaryRATUsageInformation = 1
const val PDUSessionResourceModifyIndicationTransferExtIEsPresentSecurityResult = 2

data class PDUSessionResourceModifyIndicationTransferExtIEsExtensionValue(
    val present: Int,
    val secondaryRATUsageInformation: SecondaryRATUsageInformation?,
    val securityResult: SecurityResult?
)

data class PDUSessionResourceModifyItemModCfmExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyItemModCfmExtIEsExtensionValue
)

const val PDUSessionResourceModifyItemModCfmExtIEsPresentNothing = 0

data class PDUSessionResourceModifyItemModCfmExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceModifyItemModIndExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyItemModIndExtIEsExtensionValue
)

const val PDUSessionResourceModifyItemModIndExtIEsPresentNothing = 0

data class PDUSessionResourceModifyItemModIndExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceModifyItemModReqExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyItemModReqExtIEsExtensionValue
)

const val PDUSessionResourceModifyItemModReqExtIEsPresentNothing = 0
const val PDUSessionResourceModifyItemModReqExtIEsPresentSNSSAI = 1

data class PDUSessionResourceModifyItemModReqExtIEsExtensionValue(
    val present: Int,
    val sNSSAI: SNSSAI?
)

data class PDUSessionResourceModifyItemModResExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyItemModResExtIEsExtensionValue
)

const val PDUSessionResourceModifyItemModResExtIEsPresentNothing = 0

data class PDUSessionResourceModifyItemModResExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceModifyUnsuccessfulTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceModifyUnsuccessfulTransferExtIEsExtensionValue
)

const val PDUSessionResourceModifyUnsuccessfulTransferExtIEsPresentNothing = 0

data class PDUSessionResourceModifyUnsuccessfulTransferExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceNotifyItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceNotifyItemExtIEsExtensionValue
)

const val PDUSessionResourceNotifyItemExtIEsPresentNothing = 0

data class PDUSessionResourceNotifyItemExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceNotifyReleasedTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceNotifyReleasedTransferExtIEsExtensionValue
)

const val PDUSessionResourceNotifyReleasedTransferExtIEsPresentNothing = 0
const val PDUSessionResourceNotifyReleasedTransferExtIEsPresentSecondaryRATUsageInformation = 1

data class PDUSessionResourceNotifyReleasedTransferExtIEsExtensionValue(
    val present: Int,
    val secondaryRATUsageInformation: SecondaryRATUsageInformation?
)

data class PDUSessionResourceNotifyTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceNotifyTransferExtIEsExtensionValue
)

const val PDUSessionResourceNotifyTransferExtIEsPresentNothing = 0
const val PDUSessionResourceNotifyTransferExtIEsPresentSecondaryRATUsageInformation = 1

data class PDUSessionResourceNotifyTransferExtIEsExtensionValue(
    val present: Int,
    val secondaryRATUsageInformation: SecondaryRATUsageInformation?
)

data class PDUSessionResourceReleaseCommandTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceReleaseCommandTransferExtIEsExtensionValue
)

const val PDUSessionResourceReleaseCommandTransferExtIEsPresentNothing = 0

data class PDUSessionResourceReleaseCommandTransferExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceReleasedItemNotExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceReleasedItemNotExtIEsExtensionValue
)

const val PDUSessionResourceReleasedItemNotExtIEsPresentNothing = 0

data class PDUSessionResourceReleasedItemNotExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceReleasedItemPSAckExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceReleasedItemPSAckExtIEsExtensionValue
)

const val PDUSessionResourceReleasedItemPSAckExtIEsPresentNothing = 0

data class PDUSessionResourceReleasedItemPSAckExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceReleasedItemPSFailExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceReleasedItemPSFailExtIEsExtensionValue
)

const val PDUSessionResourceReleasedItemPSFailExtIEsPresentNothing = 0

data class PDUSessionResourceReleasedItemPSFailExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceReleasedItemRelResExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceReleasedItemRelResExtIEsExtensionValue
)

const val PDUSessionResourceReleasedItemRelResExtIEsPresentNothing = 0

data class PDUSessionResourceReleasedItemRelResExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceReleaseResponseTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceReleaseResponseTransferExtIEsExtensionValue
)

const val PDUSessionResourceReleaseResponseTransferExtIEsPresentNothing = 0
const val PDUSessionResourceReleaseResponseTransferExtIEsPresentSecondaryRATUsageInformation = 1

data class PDUSessionResourceReleaseResponseTransferExtIEsExtensionValue(
    val present: Int,
    val secondaryRATUsageInformation: SecondaryRATUsageInformation?
)

data class PDUSessionResourceSecondaryRATUsageItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSecondaryRATUsageItemExtIEsExtensionValue
)

const val PDUSessionResourceSecondaryRATUsageItemExtIEsPresentNothing = 0

data class PDUSessionResourceSecondaryRATUsageItemExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceSetupItemCxtReqExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSetupItemCxtReqExtIEsExtensionValue
)

const val PDUSessionResourceSetupItemCxtReqExtIEsPresentNothing = 0

data class PDUSessionResourceSetupItemCxtReqExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceSetupItemCxtResExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSetupItemCxtResExtIEsExtensionValue
)

const val PDUSessionResourceSetupItemCxtResExtIEsPresentNothing = 0

data class PDUSessionResourceSetupItemCxtResExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceSetupItemHOReqExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSetupItemHOReqExtIEsExtensionValue
)

const val PDUSessionResourceSetupItemHOReqExtIEsPresentNothing = 0

data class PDUSessionResourceSetupItemHOReqExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceSetupItemSUReqExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSetupItemSUReqExtIEsExtensionValue
)

const val PDUSessionResourceSetupItemSUReqExtIEsPresentNothing = 0

data class PDUSessionResourceSetupItemSUReqExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceSetupItemSUResExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSetupItemSUResExtIEsExtensionValue
)

const val PDUSessionResourceSetupItemSUResExtIEsPresentNothing = 0

data class PDUSessionResourceSetupItemSUResExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceSetupResponseTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSetupResponseTransferExtIEsExtensionValue
)

const val PDUSessionResourceSetupResponseTransferExtIEsPresentNothing = 0

data class PDUSessionResourceSetupResponseTransferExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceSetupUnsuccessfulTransferExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSetupUnsuccessfulTransferExtIEsExtensionValue
)

const val PDUSessionResourceSetupUnsuccessfulTransferExtIEsPresentNothing = 0

data class PDUSessionResourceSetupUnsuccessfulTransferExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceSwitchedItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceSwitchedItemExtIEsExtensionValue
)

const val PDUSessionResourceSwitchedItemExtIEsPresentNothing = 0

data class PDUSessionResourceSwitchedItemExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceToBeSwitchedDLItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceToBeSwitchedDLItemExtIEsExtensionValue
)

const val PDUSessionResourceToBeSwitchedDLItemExtIEsPresentNothing = 0

data class PDUSessionResourceToBeSwitchedDLItemExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceToReleaseItemHOCmdExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceToReleaseItemHOCmdExtIEsExtensionValue
)

const val PDUSessionResourceToReleaseItemHOCmdExtIEsPresentNothing = 0

data class PDUSessionResourceToReleaseItemHOCmdExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionResourceToReleaseItemRelCmdExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionResourceToReleaseItemRelCmdExtIEsExtensionValue
)

const val PDUSessionResourceToReleaseItemRelCmdExtIEsPresentNothing = 0

data class PDUSessionResourceToReleaseItemRelCmdExtIEsExtensionValue(
    val present: Int
)

data class PDUSessionUsageReportExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PDUSessionUsageReportExtIEsExtensionValue
)

const val PDUSessionUsageReportExtIEsPresentNothing = 0

data class PDUSessionUsageReportExtIEsExtensionValue(
    val present: Int
)

data class PLMNSupportItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: PLMNSupportItemExtIEsExtensionValue
)

const val PLMNSupportItemExtIEsPresentNothing = 0

data class PLMNSupportItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowAcceptedItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowAcceptedItemExtIEsExtensionValue
)

const val QosFlowAcceptedItemExtIEsPresentNothing = 0

data class QosFlowAcceptedItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowAddOrModifyRequestItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowAddOrModifyRequestItemExtIEsExtensionValue
)

const val QosFlowAddOrModifyRequestItemExtIEsPresentNothing = 0

data class QosFlowAddOrModifyRequestItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowAddOrModifyResponseItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowAddOrModifyResponseItemExtIEsExtensionValue
)

const val QosFlowAddOrModifyResponseItemExtIEsPresentNothing = 0

data class QosFlowAddOrModifyResponseItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowInformationItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowInformationItemExtIEsExtensionValue
)

const val QosFlowInformationItemExtIEsPresentNothing = 0

data class QosFlowInformationItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowLevelQosParametersExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowLevelQosParametersExtIEsExtensionValue
)

const val QosFlowLevelQosParametersExtIEsPresentNothing = 0

data class QosFlowLevelQosParametersExtIEsExtensionValue(
    val present: Int
)

data class QosFlowWithCauseItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowWithCauseItemExtIEsExtensionValue
)

const val QosFlowWithCauseItemExtIEsPresentNothing = 0

data class QosFlowWithCauseItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowModifyConfirmItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowModifyConfirmItemExtIEsExtensionValue
)

const val QosFlowModifyConfirmItemExtIEsPresentNothing = 0

data class QosFlowModifyConfirmItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowNotifyItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowNotifyItemExtIEsExtensionValue
)

const val QosFlowNotifyItemExtIEsPresentNothing = 0

data class QosFlowNotifyItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowPerTNLInformationExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowPerTNLInformationExtIEsExtensionValue
)

const val QosFlowPerTNLInformationExtIEsPresentNothing = 0

data class QosFlowPerTNLInformationExtIEsExtensionValue(
    val present: Int
)

data class QosFlowPerTNLInformationItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowPerTNLInformationItemExtIEsExtensionValue
)

const val QosFlowPerTNLInformationItemExtIEsPresentNothing = 0

data class QosFlowPerTNLInformationItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowSetupRequestItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowSetupRequestItemExtIEsExtensionValue
)

const val QosFlowSetupRequestItemExtIEsPresentNothing = 0

data class QosFlowSetupRequestItemExtIEsExtensionValue(
    val present: Int
)

data class QosFlowItemWithDataForwardingExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowItemWithDataForwardingExtIEsExtensionValue
)

const val QosFlowItemWithDataForwardingExtIEsPresentNothing = 0

data class QosFlowItemWithDataForwardingExtIEsExtensionValue(
    val present: Int
)

data class QosFlowSetupResponseItemSUResExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowSetupResponseItemSUResExtIEsExtensionValue
)

const val QosFlowSetupResponseItemSUResExtIEsPresentNothing = 0

data class QosFlowSetupResponseItemSUResExtIEsExtensionValue(
    val present: Int
)

data class QosFlowToBeForwardedItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QosFlowToBeForwardedItemExtIEsExtensionValue
)

const val QosFlowToBeForwardedItemExtIEsPresentNothing = 0

data class QosFlowToBeForwardedItemExtIEsExtensionValue(
    val present: Int
)

data class QoSFlowsUsageReportItemExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: QoSFlowsUsageReportItemExtIEsExtensionValue
)

const val QoSFlowsUsageReportItemExtIEsPresentNothing = 0

data class QoSFlowsUsageReportItemExtIEsExtensionValue(
    val present: Int
)

data class RANStatusTransferTransparentContainerExtIEs(
    val id: ProtocolExtensionID,
    val criticality: Criticality,
    val extensionValue: RANStatusTransferTransparentContainerExtIEsExtensionValue
)

const val RANStatusTransferTransparentContainerExtIEsPresentNothing = 0


data class RANStatusTransferTransparentContainerExtIEsExtensionValue(
    val Present: Int
)

data class RATRestrictionsItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: RATRestrictionsItemExtIEsExtensionValue
)

const val RATRestrictionsItemExtIEsPresentNothing = 0

data class RATRestrictionsItemExtIEsExtensionValue(
    val Present: Int
)

data class RecommendedCellsForPagingExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: RecommendedCellsForPagingExtIEsExtensionValue
)

const val RecommendedCellsForPagingExtIEsPresentNothing = 0

data class RecommendedCellsForPagingExtIEsExtensionValue(
    val Present: Int
)

data class RecommendedCellItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: RecommendedCellItemExtIEsExtensionValue
)

const val RecommendedCellItemExtIEsPresentNothing = 0

data class RecommendedCellItemExtIEsExtensionValue(
    val Present: Int
)

data class RecommendedRANNodesForPagingExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: RecommendedRANNodesForPagingExtIEsExtensionValue
)

const val RecommendedRANNodesForPagingExtIEsPresentNothing = 0

data class RecommendedRANNodesForPagingExtIEsExtensionValue(
    val Present: Int
)

data class RecommendedRANNodeItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: RecommendedRANNodeItemExtIEsExtensionValue
)

const val RecommendedRANNodeItemExtIEsPresentNothing = 0

data class RecommendedRANNodeItemExtIEsExtensionValue(
    val Present: Int
)

data class SecondaryRATUsageInformationExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SecondaryRATUsageInformationExtIEsExtensionValue
)

const val SecondaryRATUsageInformationExtIEsPresentNothing = 0

data class SecondaryRATUsageInformationExtIEsExtensionValue(
    val Present: Int
)

data class SecondaryRATDataUsageReportTransferExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SecondaryRATDataUsageReportTransferExtIEsExtensionValue
)

const val SecondaryRATDataUsageReportTransferExtIEsPresentNothing = 0

data class SecondaryRATDataUsageReportTransferExtIEsExtensionValue(
    val Present: Int
)

data class SecurityContextExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SecurityContextExtIEsExtensionValue
)

const val SecurityContextExtIEsPresentNothing = 0

data class SecurityContextExtIEsExtensionValue(
    val Present: Int
)

data class SecurityIndicationExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SecurityIndicationExtIEsExtensionValue
)

const val SecurityIndicationExtIEsPresentNothing = 0
const val SecurityIndicationExtIEsPresentMaximumIntegrityProtectedDataRateDL = 1

data class SecurityIndicationExtIEsExtensionValue(
    val Present: Int,
    val MaximumIntegrityProtectedDataRateDL: MaximumIntegrityProtectedDataRate?
)

data class SecurityResultExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SecurityResultExtIEsExtensionValue
)

const val SecurityResultExtIEsPresentNothing = 0

data class SecurityResultExtIEsExtensionValue(
    val Present: Int
)

data class ServedGUAMIItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: ServedGUAMIItemExtIEsExtensionValue
)

const val ServedGUAMIItemExtIEsPresentNothing = 0

data class ServedGUAMIItemExtIEsExtensionValue(
    val Present: Int
)

data class ServiceAreaInformationItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: ServiceAreaInformationItemExtIEsExtensionValue
)

const val ServiceAreaInformationItemExtIEsPresentNothing = 0

data class ServiceAreaInformationItemExtIEsExtensionValue(
    val Present: Int
)

data class SliceOverloadItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SliceOverloadItemExtIEsExtensionValue
)

const val SliceOverloadItemExtIEsPresentNothing = 0

data class SliceOverloadItemExtIEsExtensionValue(
    val Present: Int
)

data class SliceSupportItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SliceSupportItemExtIEsExtensionValue
)

const val SliceSupportItemExtIEsPresentNothing = 0

data class SliceSupportItemExtIEsExtensionValue(
    val Present: Int
)

data class SNSSAIExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SNSSAIExtIEsExtensionValue
)

const val SNSSAIExtIEsPresentNothing = 0

data class SNSSAIExtIEsExtensionValue(
    val Present: Int
)

data class SONConfigurationTransferExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SONConfigurationTransferExtIEsExtensionValue
)

const val SONConfigurationTransferExtIEsPresentNothing = 0

data class SONConfigurationTransferExtIEsExtensionValue(
    val Present: Int
)

data class SONInformationReplyExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SONInformationReplyExtIEsExtensionValue
)

const val SONInformationReplyExtIEsPresentNothing = 0

data class SONInformationReplyExtIEsExtensionValue(
    val Present: Int
)

data class SourceNGRANNodeToTargetNGRANNodeTransparentContainerExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SourceNGRANNodeToTargetNGRANNodeTransparentContainerExtIEsExtensionValue
)

const val SourceNGRANNodeToTargetNGRANNodeTransparentContainerExtIEsPresentNothing = 0

data class SourceNGRANNodeToTargetNGRANNodeTransparentContainerExtIEsExtensionValue(
    val Present: Int
)

data class SourceRANNodeIDExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SourceRANNodeIDExtIEsExtensionValue
)

const val SourceRANNodeIDExtIEsPresentNothing = 0

data class SourceRANNodeIDExtIEsExtensionValue(
    val Present: Int
)

data class SupportedTAItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: SupportedTAItemExtIEsExtensionValue
)

const val SupportedTAItemExtIEsPresentNothing = 0

data class SupportedTAItemExtIEsExtensionValue(
    val Present: Int
)

data class TAIExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TAIExtIEsExtensionValue
)

const val TAIExtIEsPresentNothing = 0

data class TAIExtIEsExtensionValue(
    val Present: Int
)

data class TAIBroadcastEUTRAItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TAIBroadcastEUTRAItemExtIEsExtensionValue
)

const val TAIBroadcastEUTRAItemExtIEsPresentNothing = 0

data class TAIBroadcastEUTRAItemExtIEsExtensionValue(
    val Present: Int
)

data class TAIBroadcastNRItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TAIBroadcastNRItemExtIEsExtensionValue
)

const val TAIBroadcastNRItemExtIEsPresentNothing = 0

data class TAIBroadcastNRItemExtIEsExtensionValue(
    val Present: Int
)

data class TAICancelledEUTRAItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TAICancelledEUTRAItemExtIEsExtensionValue
)

const val TAICancelledEUTRAItemExtIEsPresentNothing = 0

data class TAICancelledEUTRAItemExtIEsExtensionValue(
    val Present: Int
)

data class TAICancelledNRItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TAICancelledNRItemExtIEsExtensionValue
)

const val TAICancelledNRItemExtIEsPresentNothing = 0

data class TAICancelledNRItemExtIEsExtensionValue(
    val Present: Int
)

data class TAIListForInactiveItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TAIListForInactiveItemExtIEsExtensionValue
)

const val TAIListForInactiveItemExtIEsPresentNothing = 0

data class TAIListForInactiveItemExtIEsExtensionValue(
    val Present: Int
)

data class TAIListForPagingItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TAIListForPagingItemExtIEsExtensionValue
)

const val TAIListForPagingItemExtIEsPresentNothing = 0

data class TAIListForPagingItemExtIEsExtensionValue(
    val Present: Int
)

data class TargeteNBIDExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TargeteNBIDExtIEsExtensionValue
)

const val TargeteNBIDExtIEsPresentNothing = 0

data class TargeteNBIDExtIEsExtensionValue(
    val Present: Int
)

data class TargetNGRANNodeToSourceNGRANNodeTransparentContainerExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TargetNGRANNodeToSourceNGRANNodeTransparentContainerExtIEsExtensionValue
)

const val TargetNGRANNodeToSourceNGRANNodeTransparentContainerExtIEsPresentNothing = 0

data class TargetNGRANNodeToSourceNGRANNodeTransparentContainerExtIEsExtensionValue(
    val Present: Int
)

data class TargetRANNodeIDExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TargetRANNodeIDExtIEsExtensionValue
)

const val TargetRANNodeIDExtIEsPresentNothing = 0

data class TargetRANNodeIDExtIEsExtensionValue(
    val Present: Int
)

data class TNLAssociationItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TNLAssociationItemExtIEsExtensionValue
)

const val TNLAssociationItemExtIEsPresentNothing = 0

data class TNLAssociationItemExtIEsExtensionValue(
    val Present: Int
)

data class TraceActivationExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: TraceActivationExtIEsExtensionValue
)

const val TraceActivationExtIEsPresentNothing = 0

data class TraceActivationExtIEsExtensionValue(
    val Present: Int
)

data class UEAggregateMaximumBitRateExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UEAggregateMaximumBitRateExtIEsExtensionValue
)

const val UEAggregateMaximumBitRateExtIEsPresentNothing = 0

data class UEAggregateMaximumBitRateExtIEsExtensionValue(
    val Present: Int
)

data class UEAssociatedLogicalNGConnectionItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UEAssociatedLogicalNGConnectionItemExtIEsExtensionValue
)

const val UEAssociatedLogicalNGConnectionItemExtIEsPresentNothing = 0

data class UEAssociatedLogicalNGConnectionItemExtIEsExtensionValue(
    val Present: Int
)

data class UENGAPIDPairExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UENGAPIDPairExtIEsExtensionValue
)

const val UENGAPIDPairExtIEsPresentNothing = 0

data class UENGAPIDPairExtIEsExtensionValue(
    val Present: Int
)

data class UEPresenceInAreaOfInterestItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UEPresenceInAreaOfInterestItemExtIEsExtensionValue
)

const val UEPresenceInAreaOfInterestItemExtIEsPresentNothing = 0

data class UEPresenceInAreaOfInterestItemExtIEsExtensionValue(
    val Present: Int
)

data class UERadioCapabilityForPagingExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UERadioCapabilityForPagingExtIEsExtensionValue
)

const val UERadioCapabilityForPagingExtIEsPresentNothing = 0

data class UERadioCapabilityForPagingExtIEsExtensionValue(
    val Present: Int
)

data class UESecurityCapabilitiesExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UESecurityCapabilitiesExtIEsExtensionValue
)

const val UESecurityCapabilitiesExtIEsPresentNothing = 0

data class UESecurityCapabilitiesExtIEsExtensionValue(
    val Present: Int
)

data class ULNGUUPTNLModifyItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: ULNGUUPTNLModifyItemExtIEsExtensionValue
)

const val ULNGUUPTNLModifyItemExtIEsPresentNothing = 0

data class ULNGUUPTNLModifyItemExtIEsExtensionValue(
    val Present: Int
)

data class UnavailableGUAMIItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UnavailableGUAMIItemExtIEsExtensionValue
)

const val UnavailableGUAMIItemExtIEsPresentNothing = 0

data class UnavailableGUAMIItemExtIEsExtensionValue(
    val Present: Int
)

data class UPTransportLayerInformationItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UPTransportLayerInformationItemExtIEsExtensionValue
)

const val UPTransportLayerInformationItemExtIEsPresentNothing = 0

data class UPTransportLayerInformationItemExtIEsExtensionValue(
    val Present: Int
)

data class UPTransportLayerInformationPairItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UPTransportLayerInformationPairItemExtIEsExtensionValue
)

const val UPTransportLayerInformationPairItemExtIEsPresentNothing = 0

data class UPTransportLayerInformationPairItemExtIEsExtensionValue(
    val Present: Int
)

data class UserLocationInformationEUTRAExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UserLocationInformationEUTRAExtIEsExtensionValue
)

const val UserLocationInformationEUTRAExtIEsPresentNothing = 0

data class UserLocationInformationEUTRAExtIEsExtensionValue(
    val Present: Int
)

data class UserLocationInformationN3IWFExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UserLocationInformationN3IWFExtIEsExtensionValue
)

const val UserLocationInformationN3IWFExtIEsPresentNothing = 0

data class UserLocationInformationN3IWFExtIEsExtensionValue(
    val Present: Int
)

data class UserLocationInformationNRExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UserLocationInformationNRExtIEsExtensionValue
)

const val UserLocationInformationNRExtIEsPresentNothing = 0

data class UserLocationInformationNRExtIEsExtensionValue(
    val Present: Int
)

data class UserPlaneSecurityInformationExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: UserPlaneSecurityInformationExtIEsExtensionValue
)

const val UserPlaneSecurityInformationExtIEsPresentNothing = 0

data class UserPlaneSecurityInformationExtIEsExtensionValue(
    val Present: Int
)

data class VolumeTimedReportItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: VolumeTimedReportItemExtIEsExtensionValue
)

const val VolumeTimedReportItemExtIEsPresentNothing = 0

data class VolumeTimedReportItemExtIEsExtensionValue(
    val Present: Int
)

data class XnExtTLAItemExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: XnExtTLAItemExtIEsExtensionValue
)

const val XnExtTLAItemExtIEsPresentNothing = 0

data class XnExtTLAItemExtIEsExtensionValue(
    val Present: Int
)

data class XnTNLConfigurationInfoExtIEs(
    val Id: ProtocolExtensionID,
    val Criticality: Criticality,
    val ExtensionValue: XnTNLConfigurationInfoExtIEsExtensionValue
)

const val XnTNLConfigurationInfoExtIEsPresentNothing = 0

data class XnTNLConfigurationInfoExtIEsExtensionValue(
    val Present: Int
)



