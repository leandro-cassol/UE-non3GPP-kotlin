package free5gc.ngap.ngapType

data class QosFlowAddOrModifyResponseItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val ieExtensions: ProtocolExtensionContainerQosFlowAddOrModifyResponseItemExtIEs? = null
)