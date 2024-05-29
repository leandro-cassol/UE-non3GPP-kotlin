package free5gc.ngap.ngapType

data class QosFlowNotifyItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val notificationCause: NotificationCause,
    val ieExtensions: ProtocolExtensionContainerQosFlowNotifyItemExtIEs? = null
)