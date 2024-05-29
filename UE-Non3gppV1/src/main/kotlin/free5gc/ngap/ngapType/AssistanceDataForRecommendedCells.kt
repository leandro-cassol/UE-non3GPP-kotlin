package free5gc.ngap.ngapType

data class AssistanceDataForRecommendedCells(
    val recommendedCellsForPaging: RecommendedCellsForPaging,
    val ieExtensions: ProtocolExtensionContainerAssistanceDataForRecommendedCellsExtIEs? = null
)
