package free5gc.nas.nasType

class PDUSESSIONAUTHENTICATIONRESULTMessageIdentity {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newPDUSESSIONAUTHENTICATIONRESULTMessageIdentity(): PDUSESSIONAUTHENTICATIONRESULTMessageIdentity {
            return PDUSESSIONAUTHENTICATIONRESULTMessageIdentity()
        }
    }
}


