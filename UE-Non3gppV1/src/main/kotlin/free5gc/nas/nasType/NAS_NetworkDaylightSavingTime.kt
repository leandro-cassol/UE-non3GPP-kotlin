package free5gc.nas.nasType

class NetworkDaylightSavingTime {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiNetworkDaylightSavingTime")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiNetworkDaylightSavingTime")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenNetworkDaylightSavingTime")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenNetworkDaylightSavingTime")
    fun setLen(len: UByte) {
        this.len = len
    }

    @JvmName("getValueNetworkDaylightSavingTime")
    fun getValue(): UByte {
        return octet and getBitMask(2, 0).toUByte()
    }

    @JvmName("setValueNetworkDaylightSavingTime")
    fun setValue(value: UByte) {
        octet = ((octet and 252u) + (value and 3u)).toUByte()
    }

    companion object {
        fun getBitMask(n: Int, p: Int): Int {
            return ((1 shl n) - 1) shl p
        }

        fun newNetworkDaylightSavingTime(iei: UByte): NetworkDaylightSavingTime {
            val networkDaylightSavingTime = NetworkDaylightSavingTime()
            networkDaylightSavingTime.setIei(iei)
            return networkDaylightSavingTime
        }
    }
}




