import { jsPDF } from 'jspdf'
import autoTable from 'jspdf-autotable'
import { saveAs } from 'file-saver'

/**
 * Generate NIST Evidence Pack PDF
 * Creates a professional audit-ready PDF document
 */
export function generateEvidencePack(cbomData, ghostData) {
    // Create new PDF document
    const doc = new jsPDF()
    const pageWidth = doc.internal.pageSize.getWidth()
    let yPos = 20

    // =========================================================================
    // COVER / HEADER
    // =========================================================================
    doc.setFillColor(15, 23, 42)
    doc.rect(0, 0, pageWidth, 50, 'F')

    doc.setTextColor(255, 255, 255)
    doc.setFontSize(22)
    doc.setFont('helvetica', 'bold')
    doc.text('SENTINEL-PQC', pageWidth / 2, 25, { align: 'center' })
    doc.setFontSize(12)
    doc.setFont('helvetica', 'normal')
    doc.text('Post-Quantum Cryptography Evidence Pack', pageWidth / 2, 38, { align: 'center' })

    doc.setTextColor(0, 0, 0)
    yPos = 65

    // Document Info
    doc.setFontSize(10)
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, yPos)
    yPos += 6
    doc.text('Standard: NIST SP 800-208 (Post-Quantum Cryptography)', 14, yPos)
    yPos += 15

    // =========================================================================
    // EXECUTIVE SUMMARY
    // =========================================================================
    doc.setFontSize(14)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(0, 102, 204)
    doc.text('1. Executive Summary', 14, yPos)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(0, 0, 0)
    yPos += 10

    const totalFindings = cbomData ? cbomData.length : 0
    const criticalCount = cbomData ? cbomData.filter(f => f.risk === 'CRITICAL').length : 0
    const highCount = cbomData ? cbomData.filter(f => f.risk === 'HIGH').length : 0
    const vulnerablePercent = totalFindings > 0
        ? Math.round(((criticalCount + highCount) / totalFindings) * 100)
        : 0

    doc.setFontSize(10)
    doc.text(`Total Cryptographic Call Sites: ${totalFindings}`, 14, yPos)
    yPos += 6
    doc.text(`Critical Risk: ${criticalCount}`, 14, yPos)
    yPos += 6
    doc.text(`High Risk: ${highCount}`, 14, yPos)
    yPos += 6
    doc.text(`Overall Quantum Vulnerability: ${vulnerablePercent}%`, 14, yPos)
    yPos += 15

    // =========================================================================
    // GHOST REPORT
    // =========================================================================
    doc.setFontSize(14)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(0, 102, 204)
    doc.text('2. Network Fragmentation Analysis', 14, yPos)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(0, 0, 0)
    yPos += 10

    if (ghostData) {
        const ghostDetails = [
            ['Timestamp', ghostData.timestamp || 'N/A'],
            ['Algorithm', ghostData.algorithm || 'Kyber-768'],
            ['Public Key Size', `${ghostData.public_key_size || 1184} bytes`],
            ['Handshake Size', `${ghostData.handshake_size_bytes || 0} bytes`],
            ['Safe MTU Limit', '1400 bytes'],
            ['Fragmentation Risk', ghostData.fragmentation_risk ? 'YES - CRITICAL' : 'No'],
        ]

        autoTable(doc, {
            startY: yPos,
            head: [['Metric', 'Value']],
            body: ghostDetails,
            theme: 'striped',
            headStyles: { fillColor: [15, 23, 42] },
            margin: { left: 14, right: 14 },
        })
        yPos = doc.lastAutoTable.finalY + 15
    } else {
        doc.setFontSize(10)
        doc.text('No Ghost Report data available.', 14, yPos)
        yPos += 15
    }

    // =========================================================================
    // CBOM TABLE
    // =========================================================================
    if (yPos > 200) {
        doc.addPage()
        yPos = 20
    }

    doc.setFontSize(14)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(0, 102, 204)
    doc.text('3. Cryptographic Bill of Materials', 14, yPos)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(0, 0, 0)
    yPos += 10

    if (cbomData && cbomData.length > 0) {
        const tableData = cbomData.map(item => [
            item.file?.split(/[/\\]/).pop() || 'Unknown',
            String(item.line || '?'),
            item.algo || 'Unknown',
            item.bits !== 'Unknown' ? String(item.bits) : '-',
            item.risk || 'UNKNOWN',
        ])

        autoTable(doc, {
            startY: yPos,
            head: [['File', 'Line', 'Algorithm', 'Bits', 'Risk']],
            body: tableData,
            theme: 'striped',
            headStyles: { fillColor: [15, 23, 42] },
            margin: { left: 14, right: 14 },
            styles: { fontSize: 9 },
        })
        yPos = doc.lastAutoTable.finalY + 15
    }

    // =========================================================================
    // RISK SUMMARY
    // =========================================================================
    if (yPos > 220) {
        doc.addPage()
        yPos = 20
    }

    doc.setFontSize(14)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(0, 102, 204)
    doc.text('4. Risk Assessment Summary', 14, yPos)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(0, 0, 0)
    yPos += 10

    const riskCounts = cbomData ? cbomData.reduce((acc, item) => {
        const risk = item.risk || 'UNKNOWN'
        acc[risk] = (acc[risk] || 0) + 1
        return acc
    }, {}) : {}

    const riskSummary = [
        ['CRITICAL', String(riskCounts['CRITICAL'] || 0), 'Immediately vulnerable'],
        ['HIGH', String(riskCounts['HIGH'] || 0), 'Quantum vulnerable (Shor)'],
        ['MEDIUM', String(riskCounts['MEDIUM'] || 0), 'Reduced security margin'],
        ['LOW', String(riskCounts['LOW'] || 0), 'Quantum-resistant'],
    ]

    autoTable(doc, {
        startY: yPos,
        head: [['Risk Level', 'Count', 'Description']],
        body: riskSummary,
        theme: 'striped',
        headStyles: { fillColor: [15, 23, 42] },
        margin: { left: 14, right: 14 },
    })
    yPos = doc.lastAutoTable.finalY + 15

    // =========================================================================
    // RECOMMENDATIONS
    // =========================================================================
    if (yPos > 220) {
        doc.addPage()
        yPos = 20
    }

    doc.setFontSize(14)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(0, 102, 204)
    doc.text('5. Remediation Recommendations', 14, yPos)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(0, 0, 0)
    yPos += 10

    doc.setFontSize(10)
    const recommendations = [
        '1. Replace RSA < 2048 and DES/3DES immediately.',
        '2. Plan migration of RSA/ECC to ML-KEM/ML-DSA.',
        '3. Upgrade AES-128 to AES-256.',
        '4. Implement TLS 1.3 with hybrid key exchange.',
        '5. Test with Sentinel-PQC Ghost Proxy.',
    ]

    recommendations.forEach(line => {
        doc.text(line, 14, yPos)
        yPos += 6
    })

    // =========================================================================
    // FOOTER
    // =========================================================================
    const pageCount = doc.internal.getNumberOfPages()
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i)
        doc.setFontSize(8)
        doc.setTextColor(128, 128, 128)
        doc.text(
            `Sentinel-PQC Evidence Pack | Page ${i} of ${pageCount}`,
            pageWidth / 2,
            doc.internal.pageSize.getHeight() - 10,
            { align: 'center' }
        )
    }

    // THE HEAVY HAMMER: FileSaver.js
    // =========================================================================
    const filename = `Sentinel-PQC-Evidence-Pack-${new Date().toISOString().split('T')[0]}.pdf`

    // Get the Blob directly from jsPDF
    const pdfBlob = doc.output('blob');

    // Force save using FileSaver (It handles the browser handshakes better)
    saveAs(pdfBlob, filename);

    console.log('PDF Download triggered via FileSaver:', filename);
    return true
}
