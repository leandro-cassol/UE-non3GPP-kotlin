package free5gc.nas.nasType

class ConfigurationUpdateIndication {
    var octet: UByte = 0u

    @JvmName("getIeiConfigurationUpdateIndication")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    @JvmName("setIeiConfigurationUpdateIndication")
    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    @JvmName("getREDConfigurationUpdateIndication")
    fun getRED(): UByte {
        return (octet.toInt() and getBitMask(2, 1).toInt() shr 1).toUByte()
    }

    @JvmName("setREDConfigurationUpdateIndication")
    fun setRED(red: UByte) {
        octet = (octet.toInt() and 253 or ((red.toInt() and 1) shl 1)).toUByte()
    }

    fun getACK(): UByte {
        return (octet.toInt() and getBitMask(1, 0).toInt()).toUByte()
    }

    fun setACK(ack: UByte) {
        octet = (octet.toInt() and 254 or (ack.toInt() and 1)).toUByte()
    }

    companion object {
        fun newConfigurationUpdateIndication(iei: UByte): ConfigurationUpdateIndication {
            val configurationUpdateIndication = ConfigurationUpdateIndication()
            configurationUpdateIndication.setIei(iei)
            return configurationUpdateIndication
        }

        fun getBitMask(pos: Int, len: Int): UByte {
            return ((1 shl len) - 1 shl pos).toUByte()
        }
    }
}