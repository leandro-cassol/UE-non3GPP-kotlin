package free5gc.nas.nasType

class MappedEPSBearerContexts {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiMappedEPSBearerContexts")
    fun getIei(): UByte = iei

    @JvmName("setIeiMappedEPSBearerContexts")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenMappedEPSBearerContexts")
    fun getLen(): UShort = len

    @JvmName("setLenMappedEPSBearerContexts")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getMappedEPSBearerContext(): UByteArray = buffer.copyOf()

    fun setMappedEPSBearerContext(mappedEPSBearerContext: UByteArray) {
        buffer = mappedEPSBearerContext.copyOf()
    }

    companion object{
        fun newMappedEPSBearerContexts(iei: UByte): MappedEPSBearerContexts {
            val mappedEPSBearerContexts = MappedEPSBearerContexts()
            mappedEPSBearerContexts.setIei(iei)
            return mappedEPSBearerContexts
        }
    }
}



