package free5gc.openapi.models

data class SmsSubscriptionData(
    val smsSubscribed: Boolean,
    val sharedSmsSubsDataId: List<String>
)

