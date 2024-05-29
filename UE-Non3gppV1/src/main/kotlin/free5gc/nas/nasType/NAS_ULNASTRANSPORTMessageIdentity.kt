package free5gc.nas.nasType

class ULNASTRANSPORTMessageIdentity {
    var octet: UByte = 0u

    fun getMessageType(): UByte {
        return octet
    }

    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newULNASTRANSPORTMessageIdentity(): ULNASTRANSPORTMessageIdentity {
            return ULNASTRANSPORTMessageIdentity()
        }
    }
}


