package free5gc.nas.nasType

class STATUSMessageIdentity5GMM {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newSTATUSMessageIdentity5GMM(): STATUSMessageIdentity5GMM {
            return STATUSMessageIdentity5GMM()
        }
    }
}