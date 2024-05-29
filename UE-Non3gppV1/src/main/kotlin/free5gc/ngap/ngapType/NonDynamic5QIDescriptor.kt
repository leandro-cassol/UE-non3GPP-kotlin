package free5gc.ngap.ngapType

data class NonDynamic5QIDescriptor(
    val fiveQI: FiveQI,
    val priorityLevelQos: PriorityLevelQos? = null,
    val averagingWindow: AveragingWindow? = null,
    val maximumDataBurstVolume: MaximumDataBurstVolume? = null,
    val ieExtensions: ProtocolExtensionContainerNonDynamic5QIDescriptorExtIEs? = null
)