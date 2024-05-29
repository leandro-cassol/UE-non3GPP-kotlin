package free5gc.nas.nasType

class NotificationMessageIdentity {
    var octet: UByte = 0u

    @JvmName("getMessageTypeNotificationMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeNotificationMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newNotificationMessageIdentity() = NotificationMessageIdentity()
    }
}


