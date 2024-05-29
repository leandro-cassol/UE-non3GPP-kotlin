package free5gc.ngap.ngapType

data class RecommendedCellsForPaging(
    val recommendedCellList: RecommendedCellList,
    val ieExtensions: ProtocolExtensionContainerRecommendedCellsForPagingExtIEs? = null
)