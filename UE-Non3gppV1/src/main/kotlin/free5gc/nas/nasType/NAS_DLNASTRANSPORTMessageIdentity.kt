package free5gc.nas.nasType

class DLNASTRANSPORTMessageIdentity {
    var octet: UByte = 0u

    @JvmName("getMessageTypeDLNASTRANSPORTMessageIdentity")
    fun getMessageType(): UByte {
        return octet
    }

    @JvmName("setMessageTypeDLNASTRANSPORTMessageIdentity")
    fun setMessageType(messageType: UByte) {
        octet = messageType
    }

    companion object {
        fun newDLNASTRANSPORTMessageIdentity(): DLNASTRANSPORTMessageIdentity {
            return DLNASTRANSPORTMessageIdentity()
        }
    }
}


