package free5gc.nas.nasType

class TAIList {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiTAIList")
    fun getIei(): UByte = iei

    @JvmName("setIeiTAIList")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenTAIList")
    fun getLen(): UByte = len

    @JvmName("setLenTAIList")
    fun setLen(len: UByte) {
        this.len = len
        this.buffer = UByteArray(len.toInt())
    }

    fun getPartialTrackingAreaIdentityList(): UByteArray = buffer.copyOf()

    fun setPartialTrackingAreaIdentityList(partialTrackingAreaIdentityList: UByteArray) {
        buffer = partialTrackingAreaIdentityList.copyOf()
    }

    companion object {
        fun newTAIList(iei: UByte): TAIList {
            val tAIList = TAIList()
            tAIList.setIei(iei)
            return tAIList
        }
    }
}