package engine.exchange.pkg.context

import engine.util.Util

data class N3iwfNfInfo(
    val globalN3iwfID: GlobalN3iwfID,
    val ranNodeName: String?,
    val supportedTaList: List<SupportedTaItem>
)

data class GlobalN3iwfID(
    val plmnID: PlmnID,
    val n3iwfID: UShort
)

data class SupportedTaItem(
    val tac: String,
    val broadcastPlmnList: List<BroadcastPlmnItem>
)

data class BroadcastPlmnItem(
    val plmnID: PlmnID,
    val taiSliceSupportList: List<SliceSupportItem>
)

data class PlmnID(
    val mcc: String,
    val mnc: String
)

data class SliceSupportItem(
    val snssai: SnssaiItem
)

data class SnssaiItem(
    val sst: String,
    val sd: String?
)

data class AmfSctpAddresses(
    val ipAddresses: List<String>,
    val port: Int?
) {
    fun validate(): Pair<Boolean, List<Error>> {
        val errors = mutableListOf<Error>()
        for (ipAddress in ipAddresses) {
            if (!Util().isHost(ipAddress)) {
                val err = Error("Invalid AMFSCTPAddresses.IP: $ipAddress, does not validate as IP")
                errors.add(err)
            }
        }
        return if (errors.isNotEmpty()) {
            Pair(false, errors)
        } else {
            Pair(true, emptyList())
        }
    }
}