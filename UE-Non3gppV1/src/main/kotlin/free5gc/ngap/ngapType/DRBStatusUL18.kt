package free5gc.ngap.ngapType

import free5gc.util.BitString

data class DRBStatusUL18(
    val ulCountValue: COUNTValueForPDCPSN18,
    val receiveStatusOfULPDCPSDUs: BitString? = null,
    val ieExtension: ProtocolExtensionContainerDRBStatusUL18ExtIEs? = null
)