package free5gc.nas.nasType

class MessageAuthenticationCode {
    var octet = UByteArray(4)

    @JvmName("getMACMessageAuthenticationCode")
    fun getMAC(): UByteArray {
        return octet.copyOfRange(0, 4)
    }

    @JvmName("setMACMessageAuthenticationCode")
    fun setMAC(mac: UByteArray) {
        for (i in 0..3) {
            octet[i] = mac[i]
        }
    }

    companion object {
        fun newMessageAuthenticationCode(): MessageAuthenticationCode {
            return MessageAuthenticationCode()
        }
    }
}