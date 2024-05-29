package free5gc.ngap.ngapType

data class DRBStatusDL18(
    val DLCOUNTValue: COUNTValueForPDCPSN18,
    val IEExtension: ProtocolExtensionContainerDRBStatusDL18ExtIEs? = null
)
