package free5gc.ngap.ngapType

data class QosFlowAddOrModifyRequestItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val qosFlowLevelQosParameters: QosFlowLevelQosParameters? = null,
    val erabId: ERABID? = null,
    val ieExtensions: ProtocolExtensionContainerQosFlowAddOrModifyRequestItemExtIEs? = null
)