package free5gc.nas.nasType

class ABBA {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiABBA")
    fun getIei(): UByte = iei

    @JvmName("setIeiABBA")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenABBA")
    fun getLen(): UByte = len

    @JvmName("setLenABBA")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getABBAContents(): UByteArray = buffer.copyOf()

    fun setABBAContents(aBBAContents: UByteArray) {
        buffer = aBBAContents.copyOf()
    }

    companion object {
        fun newABBA(iei: UByte): ABBA {
            val aBBA = ABBA()
            aBBA.setIei(iei)
            return aBBA
        }
    }
}