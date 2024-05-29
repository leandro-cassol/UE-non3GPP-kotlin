package free5gc.ngap.ngapType

data class RecommendedRANNodesForPaging(
    val recommendedRANNodeList: RecommendedRANNodeList,
    val ieExtensions: ProtocolExtensionContainerRecommendedRANNodesForPagingExtIEs? = null
)
