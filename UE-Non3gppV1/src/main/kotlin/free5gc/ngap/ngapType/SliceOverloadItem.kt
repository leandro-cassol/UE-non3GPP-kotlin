package free5gc.ngap.ngapType

data class SliceOverloadItem(
    val sNSSAI: SNSSAI,
    val iEExtensions: ProtocolExtensionContainerSliceOverloadItemExtIEs? = null
)