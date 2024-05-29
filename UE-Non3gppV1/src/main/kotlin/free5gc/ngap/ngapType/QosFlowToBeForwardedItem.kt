package free5gc.ngap.ngapType

data class QosFlowToBeForwardedItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val ieExtensions: ProtocolExtensionContainerQosFlowToBeForwardedItemExtIEs? = null
)
