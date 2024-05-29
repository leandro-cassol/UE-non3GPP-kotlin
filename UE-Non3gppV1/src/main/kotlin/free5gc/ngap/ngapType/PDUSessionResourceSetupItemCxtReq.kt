package free5gc.ngap.ngapType

data class PDUSessionResourceSetupItemCxtReq(
    val pDUSessionID: PDUSessionID,
    val nASPDU: NASPDU? = null,
    val sNSSAI: SNSSAI,
    val pDUSessionResourceSetupRequestTransfer: ByteArray,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceSetupItemCxtReqExtIEs? = null
)
