package free5gc.nas.nasType

class ConfigurationUpdateCommandMessageIdentity {
    var octet: UByte = 0u

    @JvmName("getMessageTypeConfigurationUpdateCommandMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeConfigurationUpdateCommandMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newConfigurationUpdateCommandMessageIdentity(): ConfigurationUpdateCommandMessageIdentity {
            return ConfigurationUpdateCommandMessageIdentity()
        }
    }
}
