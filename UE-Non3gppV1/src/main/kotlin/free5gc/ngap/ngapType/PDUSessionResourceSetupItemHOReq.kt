package free5gc.ngap.ngapType

data class PDUSessionResourceSetupItemHOReq(
    val pDUSessionID: PDUSessionID,
    val sNSSAI: SNSSAI,
    val handoverRequestTransfer: ByteArray,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceSetupItemHOReqExtIEs? = null
)


