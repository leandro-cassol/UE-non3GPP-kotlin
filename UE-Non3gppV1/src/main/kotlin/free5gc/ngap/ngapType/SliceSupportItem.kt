package free5gc.ngap.ngapType

data class SliceSupportItem(
    val sNSSAI: SNSSAI,
    val iEExtensions: ProtocolExtensionContainerSliceSupportItemExtIEs? = null
)
