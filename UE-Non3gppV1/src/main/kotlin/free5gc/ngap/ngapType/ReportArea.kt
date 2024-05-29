package free5gc.ngap.ngapType

enum class ReportAreaPresentCellValue(val value: Int) {
    ReportAreaPresentCell(0)
}

data class ReportArea(val value: ReportAreaPresentCellValue)
