package free5gc.ngap.ngapType

data class TargeteNBID(
    val globalENBID: GlobalNgENBID,
    val selectedEPSTAI: EPSTAI,
    val ieExtensions: ProtocolExtensionContainerTargeteNBIDExtIEs? = null
)