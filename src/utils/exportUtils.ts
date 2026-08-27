import { jsPDF } from 'jspdf';
import { NetworkDevice, VlanInfo } from '../types';

export interface ExportOptions {
  vlanFilter?: number | 'all';
  highRiskOnly?: boolean;
  includeNetflow?: boolean;
  includeStormMetrics?: boolean;
}

/**
 * Generates a clean, RFC-compliant CSV string and triggers a browser download.
 */
export function exportToCsv(devices: NetworkDevice[], vlans: VlanInfo[], options?: ExportOptions) {
  let filtered = [...devices];
  if (options?.vlanFilter && options.vlanFilter !== 'all') {
    filtered = filtered.filter(d => d.vlanId === options.vlanFilter);
  }
  if (options?.highRiskOnly) {
    filtered = filtered.filter(d => d.riskScore === 'High' || d.riskScore === 'Critical');
  }

  const headers = [
    'IP Address',
    'Hostname',
    'MAC Address',
    'Vendor / OUI',
    'VLAN ID',
    'VLAN Name',
    'OS Fingerprint',
    'Open Ports',
    'Hygiene Risk Score',
    'Last Seen',
    'First Seen'
  ];

  const rows = filtered.map(dev => {
    const vlan = vlans.find(v => v.id === dev.vlanId);
    const portsStr = dev.ports.map(p => `${p.port}/${p.protocol}(${p.service})`).join('; ');
    return [
      `"${dev.ip}"`,
      `"${dev.hostname}"`,
      `"${dev.mac}"`,
      `"${dev.vendor.replace(/"/g, '""')}"`,
      dev.vlanId,
      `"${vlan ? vlan.name.replace(/"/g, '""') : `VLAN ${dev.vlanId}`}"`,
      `"${dev.osFingerprint.name.replace(/"/g, '""')} (TTL:${dev.osFingerprint.initialTtl})"`,
      `"${portsStr}"`,
      `"${dev.riskScore}"`,
      `"${dev.lastSeen}"`,
      `"${dev.firstSeen}"`
    ].join(',');
  });

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `OctoLAN_Network_Audit_${new Date().toISOString().split('T')[0]}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Generates an ASCII/Plain-text formatted audit log and report.
 */
export function exportToTxt(devices: NetworkDevice[], vlans: VlanInfo[], options?: ExportOptions) {
  let filtered = [...devices];
  if (options?.vlanFilter && options.vlanFilter !== 'all') {
    filtered = filtered.filter(d => d.vlanId === options.vlanFilter);
  }
  if (options?.highRiskOnly) {
    filtered = filtered.filter(d => d.riskScore === 'High' || d.riskScore === 'Critical');
  }

  const timestamp = new Date().toISOString();
  const divider = '='.repeat(80);
  const subDivider = '-'.repeat(80);

  const lines: string[] = [
    divider,
    `OCTOLAN - ON-PREMISE NETWORK TELEMETRY & AUDIT REPORT`,
    `Generated: ${timestamp}`,
    `Auditor: POSIX Zero-Dependency C99 Sensor Suite`,
    `Total Discovered Devices: ${filtered.length} of ${devices.length}`,
    `Total VLAN Segments: ${vlans.length}`,
    divider,
    '',
    'SECTION 1: 802.1Q VLAN SEGMENTATION BREAKDOWN',
    subDivider,
  ];

  vlans.forEach(v => {
    const vDevices = devices.filter(d => d.vlanId === v.id);
    lines.push(`VLAN ID: ${v.id.toString().padEnd(4)} | Name: ${v.name.padEnd(20)} | Subnet: ${v.subnet.padEnd(18)} | Hosts: ${vDevices.length}`);
    lines.push(`  Description: ${v.description}`);
  });

  lines.push('');
  lines.push('SECTION 2: DISCOVERED HOST INVENTORY & RISK PROFILES');
  lines.push(subDivider);
  lines.push(
    `IP ADDRESS       MAC ADDRESS        VLAN  RISK      OS / HARDWARE VENDOR       PORTS`
  );
  lines.push(subDivider);

  filtered.forEach(dev => {
    const ip = dev.ip.padEnd(16);
    const mac = dev.mac.padEnd(18);
    const vlan = `VLAN ${dev.vlanId}`.padEnd(6);
    const risk = dev.riskScore.padEnd(9);
    const vendor = `${dev.vendor.slice(0, 16)} (${dev.osFingerprint.name.slice(0, 8)})`.padEnd(26);
    const ports = dev.ports.map(p => p.port).join(', ') || 'none';
    lines.push(`${ip} ${mac} ${vlan} ${risk} ${vendor} ${ports}`);
  });

  lines.push('');
  lines.push('SECTION 3: HIGH-RISK SECURITY ANOMALIES & REMEDIATIONS');
  lines.push(subDivider);

  const riskyDevices = filtered.filter(d => d.riskScore === 'High' || d.riskScore === 'Critical');
  if (riskyDevices.length === 0) {
    lines.push('No critical hygiene violations detected in selected scope.');
  } else {
    riskyDevices.forEach((dev, idx) => {
      lines.push(`[ANOMALY #${idx + 1}] ${dev.ip} (${dev.hostname || 'unnamed'}) - Risk: ${dev.riskScore}`);
      lines.push(`  - MAC: ${dev.mac} | Vendor: ${dev.vendor}`);
      lines.push(`  - OS Fingerprint: ${dev.osFingerprint.name} (TTL: ${dev.osFingerprint.initialTtl}, TCP Window: ${dev.osFingerprint.tcpWindowSize})`);
      lines.push(`  - Open Ports: ${dev.ports.map(p => `${p.port}/${p.protocol} [${p.service}] ${p.isRisky ? '(!RISKY!)' : ''}`).join(', ')}`);
      lines.push(`  - Recommended Action: Isolate host, disable unencrypted protocols, review 802.1Q ACLs.`);
      lines.push('');
    });
  }

  lines.push(divider);
  lines.push('END OF OCTOLAN TELEMETRY AUDIT REPORT');
  lines.push(divider);

  const txtContent = lines.join('\r\n');
  const blob = new Blob([txtContent], { type: 'text/plain;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `OctoLAN_Network_Audit_${new Date().toISOString().split('T')[0]}.txt`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Generates an executive, beautifully styled PDF network audit report using jsPDF.
 */
export function exportToPdf(devices: NetworkDevice[], vlans: VlanInfo[], options?: ExportOptions) {
  let filtered = [...devices];
  if (options?.vlanFilter && options.vlanFilter !== 'all') {
    filtered = filtered.filter(d => d.vlanId === options.vlanFilter);
  }
  if (options?.highRiskOnly) {
    filtered = filtered.filter(d => d.riskScore === 'High' || d.riskScore === 'Critical');
  }

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  let currentY = 18;

  // Header Banner
  doc.setFillColor(13, 17, 23); // #0d1117
  doc.rect(0, 0, pageWidth, 28, 'F');

  // Green accent bar
  doc.setFillColor(35, 134, 54); // #238636
  doc.rect(0, 28, pageWidth, 2, 'F');

  // Title & Brand
  doc.setTextColor(240, 246, 252);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text('OCTOLAN NETWORK INTELLIGENCE & AUDIT REPORT', 14, 13);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(139, 148, 158);
  doc.text(`Generated: ${new Date().toLocaleString()} | Scope: ${filtered.length} Discovered Devices | POSIX C99 Engine`, 14, 21);

  currentY = 38;

  // Executive Summary Box
  doc.setFillColor(245, 248, 250);
  doc.setDrawColor(225, 230, 235);
  doc.roundedRect(14, currentY, pageWidth - 28, 26, 2, 2, 'FD');

  const criticalCount = filtered.filter(d => d.riskScore === 'Critical' || d.riskScore === 'High').length;
  const mediumCount = filtered.filter(d => d.riskScore === 'Medium').length;
  const lowCount = filtered.filter(d => d.riskScore === 'Low').length;

  doc.setTextColor(30, 35, 42);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Executive Telemetry & Hygiene Summary', 18, currentY + 7);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(80, 85, 92);
  doc.text(`Total Monitored Hosts: ${filtered.length}   |   VLAN Segments: ${vlans.length}   |   NetFlow Sensor: eth0 (Active)`, 18, currentY + 14);

  // Status pills in summary
  doc.setTextColor(218, 54, 51); // Red
  doc.setFont('helvetica', 'bold');
  doc.text(`High/Critical Risk: ${criticalCount}`, 18, currentY + 21);

  doc.setTextColor(210, 153, 34); // Amber
  doc.text(`Medium Risk: ${mediumCount}`, 75, currentY + 21);

  doc.setTextColor(35, 134, 54); // Green
  doc.text(`Low Risk (Clean): ${lowCount}`, 130, currentY + 21);

  currentY += 34;

  // Section 1: Discovered Device Inventory
  doc.setTextColor(13, 17, 23);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text('1. Discovered Host Inventory & Port Scan Results', 14, currentY);

  currentY += 6;

  // Table Header
  doc.setFillColor(22, 27, 34);
  doc.rect(14, currentY, pageWidth - 28, 7, 'F');

  doc.setTextColor(240, 246, 252);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.text('IP ADDRESS', 16, currentY + 4.8);
  doc.text('HOSTNAME / VENDOR', 48, currentY + 4.8);
  doc.text('MAC ADDRESS', 98, currentY + 4.8);
  doc.text('VLAN', 138, currentY + 4.8);
  doc.text('OPEN PORTS', 152, currentY + 4.8);
  doc.text('RISK', 182, currentY + 4.8);

  currentY += 7;

  // Table Rows
  doc.setFontSize(8);
  filtered.forEach((dev, idx) => {
    // Check page overflow
    if (currentY > pageHeight - 20) {
      doc.addPage();
      currentY = 20;

      // Repeat Table Header
      doc.setFillColor(22, 27, 34);
      doc.rect(14, currentY, pageWidth - 28, 7, 'F');
      doc.setTextColor(240, 246, 252);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text('IP ADDRESS', 16, currentY + 4.8);
      doc.text('HOSTNAME / VENDOR', 48, currentY + 4.8);
      doc.text('MAC ADDRESS', 98, currentY + 4.8);
      doc.text('VLAN', 138, currentY + 4.8);
      doc.text('OPEN PORTS', 152, currentY + 4.8);
      doc.text('RISK', 182, currentY + 4.8);
      currentY += 7;
    }

    // Zebra striping
    if (idx % 2 === 1) {
      doc.setFillColor(248, 250, 252);
      doc.rect(14, currentY, pageWidth - 28, 6.5, 'F');
    }

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(dev.ip, 16, currentY + 4.5);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    const hostVendor = `${dev.hostname.slice(0, 14)} (${dev.vendor.slice(0, 12)})`;
    doc.text(hostVendor, 48, currentY + 4.5);

    doc.text(dev.mac, 98, currentY + 4.5);
    doc.text(`VLAN ${dev.vlanId}`, 138, currentY + 4.5);

    const portsList = dev.ports.slice(0, 3).map(p => p.port).join(', ') + (dev.ports.length > 3 ? '...' : '');
    doc.text(portsList || '-', 152, currentY + 4.5);

    // Risk color
    if (dev.riskScore === 'High' || dev.riskScore === 'Critical') {
      doc.setTextColor(218, 54, 51);
      doc.setFont('helvetica', 'bold');
    } else if (dev.riskScore === 'Medium') {
      doc.setTextColor(210, 153, 34);
      doc.setFont('helvetica', 'bold');
    } else {
      doc.setTextColor(35, 134, 54);
      doc.setFont('helvetica', 'normal');
    }
    doc.text(dev.riskScore, 182, currentY + 4.5);

    // Bottom row line
    doc.setDrawColor(235, 238, 242);
    doc.line(14, currentY + 6.5, pageWidth - 14, currentY + 6.5);

    currentY += 6.5;
  });

  currentY += 8;

  // Section 2: VLAN Segment Map
  if (currentY > pageHeight - 35) {
    doc.addPage();
    currentY = 20;
  }

  doc.setTextColor(13, 17, 23);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text('2. VLAN Segmentation & Subnet Isolation', 14, currentY);
  currentY += 6;

  vlans.forEach(v => {
    if (currentY > pageHeight - 20) {
      doc.addPage();
      currentY = 20;
    }
    const count = devices.filter(d => d.vlanId === v.id).length;
    doc.setFontSize(8.5);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 41, 59);
    doc.text(`• VLAN ${v.id} (${v.name}):`, 16, currentY + 3.5);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(`Subnet: ${v.subnet} | Gateway: ${v.gateway} | Associated Hosts: ${count}`, 60, currentY + 3.5);

    currentY += 5.5;
  });

  // Footer on all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.setFont('helvetica', 'normal');
    doc.text(`OctoLAN Network Suite • Confidential Security Audit Report • Page ${i} of ${totalPages}`, 14, pageHeight - 8);
  }

  doc.save(`OctoLAN_Security_Audit_${new Date().toISOString().split('T')[0]}.pdf`);
}
