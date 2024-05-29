package free5gc.nas.nasType

class PDUSESSIONRELEASEREQUESTMessageIdentity {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newPDUSESSIONRELEASEREQUESTMessageIdentity(): PDUSESSIONRELEASEREQUESTMessageIdentity {
            return PDUSESSIONRELEASEREQUESTMessageIdentity()
        }
    }
}


