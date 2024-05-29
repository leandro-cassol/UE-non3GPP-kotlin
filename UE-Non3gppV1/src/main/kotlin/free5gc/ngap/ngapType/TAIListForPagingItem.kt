package free5gc.ngap.ngapType

data class TAIListForPagingItem(
    val TAI: TAI,
    val IEExtensions: ProtocolExtensionContainerTAIListForPagingItemExtIEs? = null
)