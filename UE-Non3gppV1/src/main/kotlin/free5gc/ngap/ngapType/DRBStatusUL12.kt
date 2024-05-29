package free5gc.ngap.ngapType

import free5gc.util.BitString

data class DRBStatusUL12(
    val ulCountValue: COUNTValueForPDCPSN12,
    val receiveStatusOfULPDCPSDUs: BitString? = null,
    val ieExtension: ProtocolExtensionContainerDRBStatusUL12ExtIEs? = null
)
