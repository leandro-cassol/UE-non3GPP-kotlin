package free5gc.nas.nasType

class PDUSESSIONMODIFICATIONREJECTMessageIdentity {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newPDUSESSIONMODIFICATIONREJECTMessageIdentity(): PDUSESSIONMODIFICATIONREJECTMessageIdentity {
            return PDUSESSIONMODIFICATIONREJECTMessageIdentity()
        }
    }
}


