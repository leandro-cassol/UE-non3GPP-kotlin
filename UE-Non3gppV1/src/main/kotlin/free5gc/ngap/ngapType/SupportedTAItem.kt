package free5gc.ngap.ngapType

data class SupportedTAItem(
    val TAC: TAC,
    val BroadcastPLMNList: BroadcastPLMNList,
    val IEExtensions: ProtocolExtensionContainerSupportedTAItemExtIEs? = null
)

