package free5gc.ngap.ngapType

data class QosFlowModifyConfirmItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val ieExtensions: ProtocolExtensionContainerQosFlowModifyConfirmItemExtIEs? = null
)