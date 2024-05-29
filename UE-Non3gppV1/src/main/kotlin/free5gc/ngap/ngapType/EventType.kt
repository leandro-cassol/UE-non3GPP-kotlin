package free5gc.ngap.ngapType

enum class EventType(val value: Int) {
    EventTypePresentDirect(0),
    EventTypePresentChangeOfServeCell(1),
    EventTypePresentUePresenceInAreaOfInterest(2),
    EventTypePresentStopChangeOfServeCell(3),
    EventTypePresentStopUePresenceInAreaOfInterest(4),
    EventTypePresentCancelLocationReportingForTheUe(5)
}