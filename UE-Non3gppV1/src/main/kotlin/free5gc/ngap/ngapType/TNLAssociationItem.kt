package free5gc.ngap.ngapType

data class TNLAssociationItem(
    val TNLAssociationAddress: CPTransportLayerInformation,
    val Cause: Cause,
    val IEExtensions: ProtocolExtensionContainerTNLAssociationItemExtIEs? = null
)