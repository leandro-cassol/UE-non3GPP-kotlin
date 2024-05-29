package free5gc.ngap.ngapType

data class DRBsSubjectToStatusTransferItem(
    val DRBID: DRBID,
    val DRBStatusUL: DRBStatusUL,
    val DRBStatusDL: DRBStatusDL,
    val IEExtension: ProtocolExtensionContainerDRBsSubjectToStatusTransferItemExtIEs? = null
)