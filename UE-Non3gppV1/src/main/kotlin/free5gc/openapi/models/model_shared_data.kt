package free5gc.openapi.models

data class SharedData(
    val sharedDataId: String,
    val sharedAmData: AccessAndMobilitySubscriptionData?,
    val sharedSmsSubsData: SmsSubscriptionData?,
    val sharedSmsMngSubsData: SmsManagementSubscriptionData?,
    val sharedDnnConfigurations: Map<String, DnnConfiguration>,
    val sharedTraceData: TraceData?,
    val sharedSnssaiInfos: Map<String, SnssaiInfo>
)

