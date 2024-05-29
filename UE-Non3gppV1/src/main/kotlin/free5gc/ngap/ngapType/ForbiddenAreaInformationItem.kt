package free5gc.ngap.ngapType

data class ForbiddenAreaInformationItem(
    val plmnIdentity: PLMNIdentity,
    val forbiddenTACs: ForbiddenTACs,
    val ieExtensions: ProtocolExtensionContainerForbiddenAreaInformationItemExtIEs? = null
)


