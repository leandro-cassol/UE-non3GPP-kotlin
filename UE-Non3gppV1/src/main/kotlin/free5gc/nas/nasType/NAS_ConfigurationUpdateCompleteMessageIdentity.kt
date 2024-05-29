package free5gc.nas.nasType

class ConfigurationUpdateCompleteMessageIdentity {
    var octet: UByte = 0u

    companion object {
        fun newConfigurationUpdateCompleteMessageIdentity(): ConfigurationUpdateCompleteMessageIdentity {
            return ConfigurationUpdateCompleteMessageIdentity()
        }
    }

    @JvmName("getMessageTypeConfigurationUpdateCompleteMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeConfigurationUpdateCompleteMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }
}