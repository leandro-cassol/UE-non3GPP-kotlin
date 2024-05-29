package free5gc.ngap.ngapType

data class AMFTNLAssociationToAddItem(
    val amfTNLAssociationAddress: CPTransportLayerInformation,
    val tnlAssociationUsage: TNLAssociationUsage? = null,
    val tnlAddressWeightFactor: TNLAddressWeightFactor,
    val ieExtensions: ProtocolExtensionContainerAMFTNLAssociationToAddItemExtIEs? = null
)