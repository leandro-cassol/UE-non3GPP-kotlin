package free5gc.ngap.ngapType

data class PDUSessionResourceModifyItemModReq(
    val pDUSessionID: PDUSessionID,
    val nASPDU: NASPDU? = null,
    val pDUSessionResourceModifyRequestTransfer: ByteArray,
    val iEExtensions: ProtocolExtensionContainerPDUSessionResourceModifyItemModReqExtIEs? = null
)


