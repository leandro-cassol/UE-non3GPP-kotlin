package free5gc.ngap.ngapType

data class BroadcastPLMNItem(
    val plmnIdentity: PLMNIdentity,
    val taiSliceSupportList: SliceSupportList,
    val ieExtensions: ProtocolExtensionContainerBroadcastPLMNItemExtIEs? = null
)


