package free5gc.ngap.ngapType

data class QosFlowInformationItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val dlForwarding: DLForwarding? = null,
    val ieExtensions: ProtocolExtensionContainerQosFlowInformationItemExtIEs? = null
)
