package free5gc.ngap.ngapType

data class AMFTNLAssociationToRemoveItem(
    val amfTNLAssociationAddress: CPTransportLayerInformation,
    val ieExtensions: ProtocolExtensionContainerAMFTNLAssociationToRemoveItemExtIEs? = null
)