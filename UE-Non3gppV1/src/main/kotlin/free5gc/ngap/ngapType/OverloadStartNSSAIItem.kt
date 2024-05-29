package free5gc.ngap.ngapType

data class OverloadStartNSSAIItem(
    val sliceOverloadList: SliceOverloadList,
    val sliceOverloadResponse: OverloadResponse? = null,
    val sliceTrafficLoadReductionIndication: TrafficLoadReductionIndication? = null,
    val iEExtensions: ProtocolExtensionContainerOverloadStartNSSAIItemExtIEs? = null
)

