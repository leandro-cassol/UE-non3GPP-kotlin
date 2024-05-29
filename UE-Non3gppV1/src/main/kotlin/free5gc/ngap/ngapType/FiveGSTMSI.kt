package free5gc.ngap.ngapType

data class FiveGSTMSI(
    val AMFSetID: AMFSetID,
    val AMFPointer: AMFPointer,
    val FiveGTMSI: FiveGTMSI,
    val IEExtensions: ProtocolExtensionContainerFiveGSTMSIExtIEs? = null
)
