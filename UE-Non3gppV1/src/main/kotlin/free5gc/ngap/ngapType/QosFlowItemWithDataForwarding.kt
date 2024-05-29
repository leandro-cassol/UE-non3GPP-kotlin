package free5gc.ngap.ngapType

data class QosFlowItemWithDataForwarding(
    val qosFlowIdentifier: QosFlowIdentifier,
    val dataForwardingAccepted: DataForwardingAccepted? = null,
    val ieExtensions: ProtocolExtensionContainerQosFlowItemWithDataForwardingExtIEs? = null
)


