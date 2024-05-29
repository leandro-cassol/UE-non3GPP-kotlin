package free5gc.ngap.ngapType

data class UnavailableGUAMIItem(
    val GUAMI: GUAMI,
    val TimerApproachForGUAMIRemoval: TimerApproachForGUAMIRemoval? = null,
    val BackupAMFName: AMFName? = null,
    val IEExtensions: ProtocolExtensionContainerUnavailableGUAMIItemExtIEs? = null
)