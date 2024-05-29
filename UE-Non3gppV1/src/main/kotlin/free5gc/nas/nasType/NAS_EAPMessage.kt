package free5gc.nas.nasType

class EAPMessage {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = ubyteArrayOf()


    @JvmName("getIeiEAPMessage")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiEAPMessage")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenEAPMessage")
    fun getLen(): UShort {
        return len
    }

    @JvmName("setLenEAPMessage")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    @JvmName("getEAPMessageEAPMessage")
    fun getEAPMessage(): UByteArray {
        return buffer.copyOf()
    }

    @JvmName("setEAPMessageEAPMessage")
    fun setEAPMessage(eAPMessage: UByteArray) {
        eAPMessage.copyInto(buffer)
    }

    companion object {
        fun newEAPMessage(iei: UByte): EAPMessage {
            val eapMessage = EAPMessage()
            eapMessage.setIei(iei)
            return eapMessage
        }
    }
}