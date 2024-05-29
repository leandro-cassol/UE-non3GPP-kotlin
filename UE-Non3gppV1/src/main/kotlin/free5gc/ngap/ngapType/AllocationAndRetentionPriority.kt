package free5gc.ngap.ngapType

data class AllocationAndRetentionPriority(
    val priorityLevelARP: PriorityLevelARP,
    val preEmptionCapability: PreEmptionCapability,
    val preEmptionVulnerability: PreEmptionVulnerability,
    val iEExtensions: ProtocolExtensionContainerAllocationAndRetentionPriorityExtIEs? = null
)
