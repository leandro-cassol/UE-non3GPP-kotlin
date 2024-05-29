package free5gc.ngap.ngapType

data class DRBsToQosFlowsMappingItem(
    val drbId: DRBID,
    val associatedQosFlowList: AssociatedQosFlowList,
    val ieExtensions: ProtocolExtensionContainerDRBsToQosFlowsMappingItemExtIEs? = null
)