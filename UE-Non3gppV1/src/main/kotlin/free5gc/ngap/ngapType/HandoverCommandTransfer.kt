package free5gc.ngap.ngapType

data class HandoverCommandTransfer(
    val DLForwardingUPTNLInformation: UPTransportLayerInformation? = null,
    val QosFlowToBeForwardedList: QosFlowToBeForwardedList? = null,
    val DataForwardingResponseDRBList: DataForwardingResponseDRBList? = null,
    val IEExtensions: ProtocolExtensionContainerHandoverCommandTransferExtIEs? = null
)