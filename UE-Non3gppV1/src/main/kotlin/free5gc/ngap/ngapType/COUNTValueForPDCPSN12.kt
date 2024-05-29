package free5gc.ngap.ngapType

data class COUNTValueForPDCPSN12(
    val PDCPSN12: Long,
    val HFNPDCPSN12: Long,
    val IEExtensions: ProtocolExtensionContainerCOUNTValueForPDCPSN12ExtIEs? = null
)