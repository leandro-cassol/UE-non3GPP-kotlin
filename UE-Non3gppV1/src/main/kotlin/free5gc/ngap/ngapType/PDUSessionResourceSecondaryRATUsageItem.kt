package free5gc.ngap.ngapType

data class PDUSessionResourceSecondaryRATUsageItem(
    val PDUSessionID: PDUSessionID,
    val SecondaryRATDataUsageReportTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceSecondaryRATUsageItemExtIEs? = null
)
