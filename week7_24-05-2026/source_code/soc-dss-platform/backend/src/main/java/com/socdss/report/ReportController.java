package com.socdss.report;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.socdss.decision.DecisionAdvice;
import com.socdss.decision.DecisionSupportService;
import com.socdss.incident.Incident;
import com.socdss.incident.IncidentRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAdjusters;
import java.util.List;

@RestController
@RequestMapping("/api/v1/reports")
public class ReportController {
    private static final String FORMULA_PREFIXES = "=+-@";

    private final IncidentRepository incidentRepository;
    private final DecisionSupportService decisionSupportService;

    public ReportController(IncidentRepository incidentRepository, DecisionSupportService decisionSupportService) {
        this.incidentRepository = incidentRepository;
        this.decisionSupportService = decisionSupportService;
    }

    @GetMapping("/incidents.csv")
    public ResponseEntity<String> incidentsCsv(@RequestParam(required = false) String period,
                                               @RequestParam(required = false) String from,
                                               @RequestParam(required = false) String to) {
        ReportData report = reportData(period, from, to);
        StringBuilder csv = new StringBuilder();
        csv.append("id,title,incident_type,created_at,source_ip,target_asset,alert_count,max_rule_level,risk_score,risk_level,decision_priority,sla_hours,confidence,escalation,analyst_verdict,decision_status,recommendation\n");
        for (Incident i : report.incidents()) {
            DecisionAdvice advice = decisionSupportService.advise(i);
            csv.append(i.getId()).append(',')
                    .append(q(i.getTitle())).append(',')
                    .append(q(i.getIncidentType())).append(',')
                    .append(q(String.valueOf(i.getCreatedAt()))).append(',')
                    .append(q(i.getSourceIp())).append(',')
                    .append(q(i.getTargetAsset())).append(',')
                    .append(i.getAlertCount()).append(',')
                    .append(i.getMaxRuleLevel()).append(',')
                    .append(i.getRiskScore()).append(',')
                    .append(q(i.getRiskLevel())).append(',')
                    .append(q(advice.priority())).append(',')
                    .append(advice.slaHours()).append(',')
                    .append(advice.confidence()).append(',')
                    .append(q(advice.escalation())).append(',')
                    .append(q(i.getAnalystVerdict())).append(',')
                    .append(q(i.getDecisionStatus())).append(',')
                    .append(q(i.getRecommendation())).append('\n');
        }
        String filename = "incidents-" + report.label() + ".csv";
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv.toString());
    }

    @GetMapping("/incidents.pdf")
    public ResponseEntity<byte[]> incidentsPdf(@RequestParam(required = false) String period,
                                               @RequestParam(required = false) String from,
                                               @RequestParam(required = false) String to) {
        ReportData report = reportData(period, from, to);
        byte[] pdf = buildPdf(report);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=incidents-" + report.label() + ".pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }

    private ReportData reportData(String period, String from, String to) {
        TimeRange range = resolveRange(period, from, to);
        List<Incident> incidents = range == null
                ? incidentRepository.findAllByOrderByRiskScoreDesc()
                : incidentRepository.findByCreatedAtBetweenOrderByRiskScoreDesc(range.from(), range.to());
        String label = range == null ? "all" : range.label();
        return new ReportData(label, range, incidents);
    }

    private byte[] buildPdf(ReportData report) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            Document document = new Document(PageSize.A4.rotate(), 28, 28, 28, 28);
            PdfWriter.getInstance(document, output);
            document.open();

            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, Color.decode("#0f172a"));
            Font metaFont = FontFactory.getFont(FontFactory.HELVETICA, 10, Color.decode("#475569"));
            Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.WHITE);
            Font cellFont = FontFactory.getFont(FontFactory.HELVETICA, 8, Color.decode("#0f172a"));

            Paragraph title = new Paragraph("SOC DSS Decision Incident Report", titleFont);
            title.setSpacingAfter(6);
            document.add(title);

            document.add(new Paragraph("Period: " + report.label(), metaFont));
            document.add(new Paragraph("Generated at: " + Instant.now(), metaFont));
            document.add(new Paragraph("Total incidents: " + report.incidents().size(), metaFont));
            document.add(new Paragraph(" ", metaFont));

            PdfPTable summary = new PdfPTable(new float[]{1.2f, 1.2f, 1.2f, 1.2f});
            summary.setWidthPercentage(100);
            summary.addCell(summaryCell("Critical", countRisk(report.incidents(), "Critical"), Color.decode("#dc2626")));
            summary.addCell(summaryCell("High", countRisk(report.incidents(), "High"), Color.decode("#f97316")));
            summary.addCell(summaryCell("Medium", countRisk(report.incidents(), "Medium"), Color.decode("#eab308")));
            summary.addCell(summaryCell("Low", countRisk(report.incidents(), "Low"), Color.decode("#16a34a")));
            summary.setSpacingAfter(14);
            document.add(summary);

            PdfPTable table = new PdfPTable(new float[]{0.7f, 2.4f, 1.4f, 1.3f, 0.8f, 0.9f, 1.0f, 1.1f, 2.3f});
            table.setWidthPercentage(100);
            addHeader(table, headerFont, "ID", "Title", "Type", "Target", "Alerts", "Score", "Level", "Priority", "Recommendation");
            for (Incident incident : report.incidents()) {
                DecisionAdvice advice = decisionSupportService.advise(incident);
                addCell(table, cellFont, String.valueOf(incident.getId()));
                addCell(table, cellFont, clean(incident.getTitle()));
                addCell(table, cellFont, clean(incident.getIncidentType()));
                addCell(table, cellFont, clean(incident.getTargetAsset()));
                addCell(table, cellFont, String.valueOf(incident.getAlertCount()));
                addCell(table, cellFont, String.valueOf(incident.getRiskScore()));
                addCell(table, cellFont, clean(incident.getRiskLevel()));
                addCell(table, cellFont, clean(advice.priority()));
                addCell(table, cellFont, clean(incident.getRecommendation()));
            }
            document.add(table);
            document.close();
            return output.toByteArray();
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to generate PDF report", e);
        }
    }

    private PdfPCell summaryCell(String label, long value, Color color) {
        Font labelFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.WHITE);
        PdfPCell cell = new PdfPCell(new Phrase(label + "\n" + value, labelFont));
        cell.setBackgroundColor(color);
        cell.setPadding(10);
        cell.setHorizontalAlignment(Element.ALIGN_CENTER);
        return cell;
    }

    private void addHeader(PdfPTable table, Font font, String... values) {
        for (String value : values) {
            PdfPCell cell = new PdfPCell(new Phrase(value, font));
            cell.setBackgroundColor(Color.decode("#1e293b"));
            cell.setPadding(6);
            table.addCell(cell);
        }
    }

    private void addCell(PdfPTable table, Font font, String value) {
        PdfPCell cell = new PdfPCell(new Phrase(value == null ? "" : value, font));
        cell.setPadding(5);
        table.addCell(cell);
    }

    private long countRisk(List<Incident> incidents, String level) {
        return incidents.stream().filter(i -> level.equalsIgnoreCase(i.getRiskLevel())).count();
    }

    private String clean(String value) {
        if (value == null) return "";
        return value.replace('\r', ' ').replace('\n', ' ');
    }

    private TimeRange resolveRange(String period, String from, String to) {
        if (from != null && to != null) {
            return new TimeRange(LocalDate.parse(from).atStartOfDay().toInstant(ZoneOffset.UTC),
                    LocalDate.parse(to).plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC),
                    from + "-to-" + to);
        }
        if (period == null || period.isBlank()) {
            return null;
        }
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        LocalDate start = switch (period.toLowerCase()) {
            case "week" -> today.with(TemporalAdjusters.previousOrSame(java.time.DayOfWeek.MONDAY));
            case "month" -> today.withDayOfMonth(1);
            case "year" -> today.withDayOfYear(1);
            default -> null;
        };
        if (start == null) {
            return null;
        }
        return new TimeRange(start.atStartOfDay().toInstant(ZoneOffset.UTC),
                today.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC),
                period.toLowerCase());
    }

    private String q(String value) {
        if (value == null) return "\"\"";
        String sanitized = value.replace('\r', ' ').replace('\n', ' ');
        String formulaCheck = sanitized.stripLeading();
        if (!formulaCheck.isEmpty()) {
            char first = formulaCheck.charAt(0);
            if (FORMULA_PREFIXES.indexOf(first) >= 0 || first == '\t') {
                sanitized = "'" + sanitized;
            }
        }
        return "\"" + sanitized.replace("\"", "\"\"") + "\"";
    }

    private record TimeRange(Instant from, Instant to, String label) {}
    private record ReportData(String label, TimeRange range, List<Incident> incidents) {}
}
