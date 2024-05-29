package free5gc.ngap.ngapType

data class QosFlowSetupRequestItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val qosFlowLevelQosParameters: QosFlowLevelQosParameters,
    val erabId: ERABID? = null,
    val ieExtensions: ProtocolExtensionContainerQosFlowSetupRequestItemExtIEs? = null
)