package free5gc.ngap.ngapType

data class GBRQosInformation(
    val maximumFlowBitRateDL: BitRate,
    val maximumFlowBitRateUL: BitRate,
    val guaranteedFlowBitRateDL: BitRate,
    val guaranteedFlowBitRateUL: BitRate,
    val notificationControl: NotificationControl? = null,
    val maximumPacketLossRateDL: PacketLossRate? = null,
    val maximumPacketLossRateUL: PacketLossRate? = null,
    val ieExtensions: ProtocolExtensionContainerGBRQosInformationExtIEs? = null
)


