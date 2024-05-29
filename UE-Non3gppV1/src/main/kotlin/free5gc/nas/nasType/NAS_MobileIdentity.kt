package free5gc.nas.nasType

class MobileIdentity {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiMobileIdentity")
    fun getIei(): UByte = iei

    @JvmName("setIeiMobileIdentity")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenMobileIdentity")
    fun getLen(): UShort = len

    @JvmName("setLenMobileIdentity")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getMobileIdentityContents(): UByteArray = buffer.copyOf()

    fun setMobileIdentityContents(mobileIdentityContents: UByteArray) {
        buffer = mobileIdentityContents.copyOf()
    }

    companion object {
        fun newMobileIdentity(iei: UByte): MobileIdentity {
            val mobileIdentity = MobileIdentity()
            mobileIdentity.setIei(iei)
            return mobileIdentity
        }
    }
}