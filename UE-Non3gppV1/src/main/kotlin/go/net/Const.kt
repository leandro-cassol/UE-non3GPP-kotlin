package go.net

class ConstNet {
    val classAMask = IPMask().iPv4Mask(0xff.toByte(), 0, 0, 0)
    val classBMask = IPMask().iPv4Mask(0xff.toByte(), 0xff.toByte(), 0, 0)
    val classCMask = IPMask().iPv4Mask(0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0)


    val IPv4bcast = IP().iPv4(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte())
    val IPv4allsys = IP().iPv4(224.toByte(), 0, 0, 1)
    val IPv4allrouter = IP().iPv4(224.toByte(), 0, 0, 2)
    val IPv4zero = IP().iPv4(0, 0, 0, 0)
    val IPv6zero = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    val IPv6unspecified = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    val IPv6loopback = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    val IPv6interfacelocalallnodes = byteArrayOf(0xff.toByte(), 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01)
    val IPv6linklocalallnodes = byteArrayOf(0xff.toByte(), 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01)
    val IPv6linklocalallrouters = byteArrayOf(0xff.toByte(), 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02)

    val v4InV6Prefix = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff.toByte(), 0xff.toByte())
}