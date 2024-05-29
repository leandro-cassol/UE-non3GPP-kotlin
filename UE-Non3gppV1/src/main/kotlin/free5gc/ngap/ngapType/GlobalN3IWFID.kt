package free5gc.ngap.ngapType

data class GlobalN3IWFID(
    val plmnIdentity: PLMNIdentity,
    val n3iwfId: N3IWFID,
    val ieExtensions: ProtocolExtensionContainerGlobalN3IWFIDExtIEs? = null
)

