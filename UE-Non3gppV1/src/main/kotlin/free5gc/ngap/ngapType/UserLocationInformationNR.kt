package free5gc.ngap.ngapType

data class UserLocationInformationNR(
    val NRCGI: NRCGI,
    val TAI: TAI,
    val TimeStamp: TimeStamp? = null,
    val IEExtensions: ProtocolExtensionContainerUserLocationInformationNRExtIEs? = null
)
