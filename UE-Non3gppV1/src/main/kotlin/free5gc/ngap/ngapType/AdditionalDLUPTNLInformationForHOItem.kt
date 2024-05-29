package free5gc.ngap.ngapType


class AdditionalDLUPTNLInformationForHOItem(
    val additionalDLNGUUPTNLInformation: UPTransportLayerInformation,
    val additionalQosFlowSetupResponseList: QosFlowListWithDataForwarding,
    val additionalDLForwardingUPTNLInformation: UPTransportLayerInformation?,
    val ieExtensions: ProtocolExtensionContainerAdditionalDLUPTNLInformationForHOItemExtIEs?
)
