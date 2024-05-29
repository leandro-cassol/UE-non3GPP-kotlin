package free5gc.ngap.ngapType

data class SourceNGRANNodeToTargetNGRANNodeTransparentContainer(
    val rrcContainer: RRCContainer,
    val pduSessionResourceInformationList: PDUSessionResourceInformationList? = null,
    val erabInformationList: ERABInformationList? = null,
    val targetCellID: NGRANCGI,
    val indexToRFSP: IndexToRFSP? = null,
    val ueHistoryInformation: UEHistoryInformation,
    val ieExtensions: ProtocolExtensionContainerSourceNGRANNodeToTargetNGRANNodeTransparentContainerExtIEs? = null
)
