package free5gc.nas.nasType

class PDUSESSIONRELEASECOMMANDMessageIdentity {
    var octet: UByte = 0u

    companion object {
        fun newPDUSESSIONRELEASECOMMANDMessageIdentity() = PDUSESSIONRELEASECOMMANDMessageIdentity()
    }

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }
}

