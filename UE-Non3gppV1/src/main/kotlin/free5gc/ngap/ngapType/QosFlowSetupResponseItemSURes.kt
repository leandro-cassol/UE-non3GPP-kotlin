package free5gc.ngap.ngapType

data class QosFlowSetupResponseItemSURes(
    val qosFlowIdentifier: QosFlowIdentifier,
    val ieExtensions: ProtocolExtensionContainerQosFlowSetupResponseItemSUResExtIEs? = null
)
