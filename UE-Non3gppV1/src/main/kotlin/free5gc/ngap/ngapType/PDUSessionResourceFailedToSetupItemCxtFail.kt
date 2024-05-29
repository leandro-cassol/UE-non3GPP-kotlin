package free5gc.ngap.ngapType

data class PDUSessionResourceFailedToSetupItemCxtFail(
    val PDUSessionID: PDUSessionID,
    val PDUSessionResourceSetupUnsuccessfulTransfer: ByteArray,
    val IEExtensions: ProtocolExtensionContainerPDUSessionResourceFailedToSetupItemCxtFailExtIEs? = null
)


