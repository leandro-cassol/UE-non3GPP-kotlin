package free5gc.ngap.ngapType

data class QosFlowWithCauseItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val cause: Cause, // Assuming Cause is an enum or a class with a range of 0 to 5
    val ieExtensions: ProtocolExtensionContainerQosFlowWithCauseItemExtIEs? = null // Assuming ProtocolExtensionContainerQosFlowWithCauseItemExtIEs is a class
)