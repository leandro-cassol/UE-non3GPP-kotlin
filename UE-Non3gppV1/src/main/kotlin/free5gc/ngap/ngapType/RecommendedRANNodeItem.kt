package free5gc.ngap.ngapType

data class RecommendedRANNodeItem(
    val aMFPagingTarget: AMFPagingTarget,
    val iEExtensions: ProtocolExtensionContainerRecommendedRANNodeItemExtIEs? = null
)