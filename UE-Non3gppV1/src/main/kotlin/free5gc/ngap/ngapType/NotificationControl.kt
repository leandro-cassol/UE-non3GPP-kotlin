package free5gc.ngap.ngapType

data class NotificationControl(val value: NotificationControlPresentNotificationRequested)

enum class NotificationControlPresentNotificationRequested(val value: Int) {
    NotificationRequested(0)
}
