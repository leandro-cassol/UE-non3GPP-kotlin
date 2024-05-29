package free5gc.ngap.ngapType

data class UERadioCapabilityForPaging(
    val UERadioCapabilityForPagingOfNR: UERadioCapabilityForPagingOfNR? = null,
    val UERadioCapabilityForPagingOfEUTRA: UERadioCapabilityForPagingOfEUTRA? = null,
    val IEExtensions: ProtocolExtensionContainerUERadioCapabilityForPagingExtIEs? = null
)