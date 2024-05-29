package free5gc.nas.nasType

class NotificationResponseMessageIdentity {
    var octet: UByte = 0u

    @JvmName("getMessageTypeNotificationResponseMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeNotificationResponseMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newNotificationResponseMessageIdentity(): NotificationResponseMessageIdentity {
            return NotificationResponseMessageIdentity()
        }
    }
}


