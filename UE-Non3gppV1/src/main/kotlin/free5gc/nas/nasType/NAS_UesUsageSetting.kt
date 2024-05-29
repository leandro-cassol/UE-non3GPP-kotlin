package free5gc.nas.nasType

class UesUsageSetting {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    companion object {
        fun newUesUsageSetting(iei: UByte): UesUsageSetting {
            val uesUsageSetting = UesUsageSetting()
            uesUsageSetting.setIei(iei)
            return uesUsageSetting
        }

        private fun getBitMask(pos: Int, len: Int): Int {
            return ((1 shl len) - 1) shl pos
        }
    }

    @JvmName("getIeiUesUsageSetting")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiUesUsageSetting")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenUesUsageSetting")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenUesUsageSetting")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getUesUsageSetting(): UByte {
        return octet and getBitMask(1, 0).toUByte()
    }

    fun setUesUsageSetting(uesUsageSetting: UByte) {
        octet = ((octet and 254u) + (uesUsageSetting and 1u)).toUByte()
    }
}

