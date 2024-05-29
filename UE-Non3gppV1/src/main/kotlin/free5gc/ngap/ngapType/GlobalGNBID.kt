package free5gc.ngap.ngapType

data class GlobalGNBID(
    val plmnIdentity: PLMNIdentity,
    val gnbId: GNBID,
    val ieExtensions: ProtocolExtensionContainerGlobalGNBIDExtIEs? = null
)


