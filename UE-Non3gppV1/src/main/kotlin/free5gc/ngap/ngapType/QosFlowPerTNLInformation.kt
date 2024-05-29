package free5gc.ngap.ngapType

data class QosFlowPerTNLInformation(
    val upTransportLayerInformation: UPTransportLayerInformation,
    val associatedQosFlowList: AssociatedQosFlowList,
    val ieExtensions: ProtocolExtensionContainerQosFlowPerTNLInformationExtIEs? = null
)
