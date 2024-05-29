package free5gc.ngap.ngapType

data class QosFlowAcceptedItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val ieExtensions: ProtocolExtensionContainerQosFlowAcceptedItemExtIEs? = null
)
