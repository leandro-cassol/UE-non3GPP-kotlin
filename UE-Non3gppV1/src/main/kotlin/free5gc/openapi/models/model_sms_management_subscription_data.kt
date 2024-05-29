package free5gc.openapi.models

data class SmsManagementSubscriptionData(
    val supportedFeatures: String,
    val mtSmsSubscribed: Boolean,
    val mtSmsBarringAll: Boolean,
    val mtSmsBarringRoaming: Boolean,
    val moSmsSubscribed: Boolean,
    val moSmsBarringAll: Boolean,
    val moSmsBarringRoaming: Boolean,
    val sharedSmsMngDataIds: List<String>
)
