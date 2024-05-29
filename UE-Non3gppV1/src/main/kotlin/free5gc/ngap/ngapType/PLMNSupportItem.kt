package free5gc.ngap.ngapType

data class PLMNSupportItem(
    val plmnIdentity: PLMNIdentity,
    val sliceSupportList: SliceSupportList,
    val ieExtensions: ProtocolExtensionContainerPLMNSupportItemExtIEs? = null
)