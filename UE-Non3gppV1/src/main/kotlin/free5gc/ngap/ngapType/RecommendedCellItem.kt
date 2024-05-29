package free5gc.ngap.ngapType

data class RecommendedCellItem(
    val nGRANCGI: NGRANCGI,
    val timeStayedInCell: Int? = null,
    val iEExtensions: ProtocolExtensionContainerRecommendedCellItemExtIEs? = null
)
