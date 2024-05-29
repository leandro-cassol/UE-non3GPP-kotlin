package free5gc.ngap.ngapType

data class InfoOnRecommendedCellsAndRANNodesForPaging(
    val recommendedCellsForPaging: RecommendedCellsForPaging,
    val recommendRANNodesForPaging: RecommendedRANNodesForPaging,
    val ieExtensions: ProtocolExtensionContainerInfoOnRecommendedCellsAndRANNodesForPagingExtIEs? = null
)
