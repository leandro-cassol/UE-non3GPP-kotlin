package free5gc.ngap.ngapType

data class UserLocationInformationEUTRA(
    val EUTRACGI: EUTRACGI,
    val TAI: TAI,
    val TimeStamp: TimeStamp? = null,
    val IEExtensions: ProtocolExtensionContainerUserLocationInformationEUTRAExtIEs? = null
)