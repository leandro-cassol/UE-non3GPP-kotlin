package free5gc.ngap.ngapType

data class NRCGI(
    val plmnIdentity: PLMNIdentity,
    val nrCellIdentity: NRCellIdentity,
    val ieExtensions: ProtocolExtensionContainerNRCGIExtIEs? = null
)