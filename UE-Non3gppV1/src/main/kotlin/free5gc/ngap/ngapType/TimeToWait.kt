package free5gc.ngap.ngapType

enum class TimeToWaitPresent(val value: Int) {
    V1s(0),
    V2s(1),
    V5s(2),
    V10s(3),
    V20s(4),
    V60s(5)
}

class TimeToWait(val value: TimeToWaitPresent)
