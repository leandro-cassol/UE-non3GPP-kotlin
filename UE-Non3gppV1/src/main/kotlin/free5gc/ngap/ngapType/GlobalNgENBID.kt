package free5gc.ngap.ngapType

data class GlobalNgENBID(
    val pLMNIdentity: PLMNIdentity,
    val ngENBID: NgENBID,
    val iEExtensions: ProtocolExtensionContainerGlobalNgENBIDExtIEs? = null
)
