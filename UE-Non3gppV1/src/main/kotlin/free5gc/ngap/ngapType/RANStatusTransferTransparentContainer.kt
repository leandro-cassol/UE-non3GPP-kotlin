package free5gc.ngap.ngapType

data class RANStatusTransferTransparentContainer(
    val dRBsSubjectToStatusTransferList: DRBsSubjectToStatusTransferList,
    val iEExtensions: ProtocolExtensionContainerRANStatusTransferTransparentContainerExtIEs? = null
)
