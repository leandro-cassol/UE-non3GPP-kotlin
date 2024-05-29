package free5gc.ngap.ngapType

data class AMFTNLAssociationToUpdateItem(
    val AMFTNLAssociationAddress: CPTransportLayerInformation,
    val TNLAssociationUsage: TNLAssociationUsage? = null,
    val TNLAddressWeightFactor: TNLAddressWeightFactor? = null,
    val IEExtensions: ProtocolExtensionContainerAMFTNLAssociationToUpdateItemExtIEs? = null
)