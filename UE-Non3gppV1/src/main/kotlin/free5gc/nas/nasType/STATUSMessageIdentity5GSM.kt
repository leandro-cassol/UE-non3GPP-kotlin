package free5gc.nas.nasType

class STATUSMessageIdentity5GSM {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newSTATUSMessageIdentity5GSM(): STATUSMessageIdentity5GSM {
            return STATUSMessageIdentity5GSM()
        }
    }
}