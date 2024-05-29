package free5gc.nas.nasType

class ServiceAreaList {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiServiceAreaList")
    fun getIei(): UByte = iei

    @JvmName("setIeiServiceAreaList")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenServiceAreaList")
    fun getLen(): UByte = len

    @JvmName("setLenServiceAreaList")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getPartialServiceAreaList(): UByteArray = buffer.copyOf()

    fun setPartialServiceAreaList(partialServiceAreaList: UByteArray) {
        buffer = partialServiceAreaList.copyOf()
    }

    companion object {
        fun newServiceAreaList(iei: UByte): ServiceAreaList {
            val serviceAreaList = ServiceAreaList()
            serviceAreaList.setIei(iei)
            return serviceAreaList
        }
    }
}