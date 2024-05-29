package free5gc.ngap.ngapType

data class QosFlowLevelQosParameters(
    val qosCharacteristics: QosCharacteristics,
    val allocationAndRetentionPriority: AllocationAndRetentionPriority,
    val gbrQosInformation: GBRQosInformation? = null,
    val reflectiveQosAttribute: ReflectiveQosAttribute? = null,
    val additionalQosFlowInformation: AdditionalQosFlowInformation? = null,
    val ieExtensions: ProtocolExtensionContainerQosFlowLevelQosParametersExtIEs? = null
)
