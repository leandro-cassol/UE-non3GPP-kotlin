package free5gc.nas.nasType

class PDUSESSIONAUTHENTICATIONCOMMANDMessageIdentity() {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newPDUSESSIONAUTHENTICATIONCOMMANDMessageIdentity(): PDUSESSIONAUTHENTICATIONCOMMANDMessageIdentity {
            return PDUSESSIONAUTHENTICATIONCOMMANDMessageIdentity()
        }
    }
}