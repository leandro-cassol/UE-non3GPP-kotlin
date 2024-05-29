package free5gc.ngap.ngapType

data class QosFlowPerTNLInformationItem(
    val qosFlowPerTNLInformation: QosFlowPerTNLInformation,
    val ieExtensions: ProtocolExtensionContainerQosFlowPerTNLInformationItemExtIEs? = null
)