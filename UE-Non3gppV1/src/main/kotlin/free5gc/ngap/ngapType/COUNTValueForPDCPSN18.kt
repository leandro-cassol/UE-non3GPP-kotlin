package free5gc.ngap.ngapType

data class COUNTValueForPDCPSN18(
    val PDCPSN18: Long,
    val HFNPDCPSN18: Long,
    val IEExtensions: ProtocolExtensionContainerCOUNTValueForPDCPSN18ExtIEs? = null
)