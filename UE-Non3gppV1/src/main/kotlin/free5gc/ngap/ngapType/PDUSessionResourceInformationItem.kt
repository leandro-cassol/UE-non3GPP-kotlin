package free5gc.ngap.ngapType

data class PDUSessionResourceInformationItem(
    val pDUSessionID: PDUSessionID,
    val qosFlowInformationList: QosFlowInformationList,
    val dRBsToQosFlowsMappingList: DRBsToQosFlowsMappingList? = null,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceInformationItemExtIEs? = null
)