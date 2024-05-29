package free5gc.ngap.ngapType

data class ServedGUAMIItem(
    val GUAMI: GUAMI,
    val BackupAMFName: AMFName? = null,
    val IEExtensions: ProtocolExtensionContainerServedGUAMIItemExtIEs? = null
)