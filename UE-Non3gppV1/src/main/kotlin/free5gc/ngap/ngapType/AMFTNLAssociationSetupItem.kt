package free5gc.ngap.ngapType

data class AMFTNLAssociationSetupItem(
    val amfTNLAssociationAddress: CPTransportLayerInformation,
    val ieExtensions: ProtocolExtensionContainerAMFTNLAssociationSetupItemExtIEs? = null
)