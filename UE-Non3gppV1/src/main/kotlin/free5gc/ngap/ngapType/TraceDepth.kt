package free5gc.ngap.ngapType

enum class TraceDepth(val value: Int) {
    TraceDepthPresentMinimum(0),
    TraceDepthPresentMedium(1),
    TraceDepthPresentMaximum(2),
    TraceDepthPresentMinimumWithoutVendorSpecificExtension(3),
    TraceDepthPresentMediumWithoutVendorSpecificExtension(4),
    TraceDepthPresentMaximumWithoutVendorSpecificExtension(5)
}


