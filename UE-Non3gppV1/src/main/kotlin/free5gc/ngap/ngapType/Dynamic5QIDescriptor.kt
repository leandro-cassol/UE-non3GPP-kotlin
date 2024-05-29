package free5gc.ngap.ngapType

data class Dynamic5QIDescriptor(
    val priorityLevelQos: PriorityLevelQos,
    val packetDelayBudget: PacketDelayBudget,
    val packetErrorRate: PacketErrorRate,
    val fiveQI: FiveQI? = null,
    val delayCritical: DelayCritical? = null,
    val averagingWindow: AveragingWindow? = null,
    val maximumDataBurstVolume: MaximumDataBurstVolume? = null,
    val ieExtensions: ProtocolExtensionContainerDynamic5QIDescriptorExtIEs? = null
)

