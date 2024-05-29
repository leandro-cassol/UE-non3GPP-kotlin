package free5gc.ngap.ngapType

data class DRBStatusDL12(
    val DLCOUNTValue: COUNTValueForPDCPSN12,
    val IEExtension: ProtocolExtensionContainerDRBStatusDL12ExtIEs? = null
)