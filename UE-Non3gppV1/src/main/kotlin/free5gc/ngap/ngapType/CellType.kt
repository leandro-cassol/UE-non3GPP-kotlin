package free5gc.ngap.ngapType

data class CellType(
    val cellSize: CellSize,
    val ieExtensions: ProtocolExtensionContainerCellTypeExtIEs? = null
)


