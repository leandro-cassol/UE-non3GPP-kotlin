package free5gc.ngap.ngapType

data class ServiceAreaInformationItem(
    val plmnIdentity: PLMNIdentity,
    val allowedTACs: AllowedTACs? = null,
    val notAllowedTACs: NotAllowedTACs? = null,
    val ieExtensions: ProtocolExtensionContainerServiceAreaInformationItemExtIEs? = null
)
