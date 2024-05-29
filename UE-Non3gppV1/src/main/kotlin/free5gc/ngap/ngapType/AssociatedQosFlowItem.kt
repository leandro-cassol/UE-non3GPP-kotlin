package free5gc.ngap.ngapType

data class AssociatedQosFlowItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val qosFlowMappingIndication: Int? = null, // Assuming aper.Enumerated is a simple enumeration that can be represented as an Int in Kotlin
    val ieExtensions: ProtocolExtensionContainerAssociatedQosFlowItemExtIEs? = null
)