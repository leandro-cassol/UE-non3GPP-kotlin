package free5gc.ngap.ngapType

data class PDUSessionResourceFailedToSetupItemPSReq(
    val PDUSessionID: PDUSessionID,
    val PathSwitchRequestSetupFailedTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceFailedToSetupItemPSReqExtIEs? = null
)


