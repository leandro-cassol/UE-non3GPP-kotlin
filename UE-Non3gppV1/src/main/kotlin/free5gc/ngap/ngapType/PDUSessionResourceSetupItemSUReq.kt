package free5gc.ngap.ngapType

data class PDUSessionResourceSetupItemSUReq(
    val pDUSessionID: PDUSessionID,
    val pDUSessionNASPDU: NASPDU? = null,
    val sNSSAI: SNSSAI,
    val pDUSessionResourceSetupRequestTransfer: ByteArray,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceSetupItemSUReqExtIEs? = null
)
