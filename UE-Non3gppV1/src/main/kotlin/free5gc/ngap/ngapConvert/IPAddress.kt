package free5gc.ngap.ngapConvert

import free5gc.util.BitString
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress


fun ipAddressToString(ipAddr: free5gc.ngap.ngapType.TransportLayerAddress): Pair<String, String> {
    val ip = ipAddr.value
    var ipv4Addr = ""
    var ipv6Addr = ""

    when (ip.bitLength.toInt()) {
        32 -> {
            val netIP = InetAddress.getByAddress(ip.bytes.sliceArray(0..3)) as Inet4Address
            ipv4Addr = netIP.hostAddress
        }
        128 -> {
            val netIP = InetAddress.getByAddress(ip.bytes) as Inet6Address
            ipv6Addr = netIP.hostAddress
        }
        160 -> {
            val netIPv4 = InetAddress.getByAddress(ip.bytes.sliceArray(0..3)) as Inet4Address
            val netIPv6 = InetAddress.getByAddress(ip.bytes.sliceArray(4 until ip.bytes.size)) as Inet6Address
            ipv4Addr = netIPv4.hostAddress
            ipv6Addr = netIPv6.hostAddress
        }
    }
    return Pair(ipv4Addr, ipv6Addr)
}

fun ipAddressToNgap(ipv4Addr: String?, ipv6Addr: String?): free5gc.ngap.ngapType.TransportLayerAddress {
    if (ipv4Addr.isNullOrEmpty() && ipv6Addr.isNullOrEmpty()) {
        println("IPAddressToNgap: Both ipv4 & ipv6 are nil string")
        return free5gc.ngap.ngapType.TransportLayerAddress(BitString(byteArrayOf(), 0U))
    }

    var ipBytes = ByteArray(0)
    var bitLength = 0

    if (!ipv4Addr.isNullOrEmpty() && !ipv6Addr.isNullOrEmpty()) {
        val ipv4NetIP = InetAddress.getByName(ipv4Addr) as Inet4Address
        val ipv6NetIP = InetAddress.getByName(ipv6Addr) as Inet6Address
        for (b in ipv4NetIP.address) {
            ipBytes += b
        }
        for (b in ipv6NetIP.address) {
            ipBytes += b
        }
        bitLength = 160
    } else if (!ipv4Addr.isNullOrEmpty()) {
        val ipv4NetIP = InetAddress.getByName(ipv4Addr) as Inet4Address
        for (b in ipv4NetIP.address) {
            ipBytes += b
        }
        bitLength = 32
    } else if (!ipv6Addr.isNullOrEmpty()) {
        val ipv6NetIP = InetAddress.getByName(ipv6Addr) as Inet6Address
        for (b in ipv6NetIP.address) {
            ipBytes += b
        }
        bitLength = 128
    }

    return free5gc.ngap.ngapType.TransportLayerAddress(BitString(ipBytes, bitLength.toULong()))
}


