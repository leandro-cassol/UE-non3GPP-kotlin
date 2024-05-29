package free5gc.ngap.ngapType

data class ERABInformationItem(
    val ERABID: ERABID,
    val DLForwarding: DLForwarding? = null,
    val IEExtensions: ProtocolExtensionContainerERABInformationItemExtIEs? = null
)