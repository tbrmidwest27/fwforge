const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, LevelFormat, TableOfContents, HeadingLevel, BorderStyle,
  WidthType, ShadingType, Footer, PageNumber, TabStopType, TabStopPosition,
  PageBreak,
} = require("docx");

// ---------- helpers ----------
const H = HeadingLevel;
const W = WidthType.DXA;
const CONTENT = 9360; // US Letter, 1" margins

const R = (text, o = {}) => new TextRun({ text, ...o });
const B = (text, o = {}) => new TextRun({ text, bold: true, ...o });
const P = (children, o = {}) =>
  new Paragraph({
    spacing: { after: 120 },
    children: typeof children === "string" ? [R(children)] : children,
    ...o,
  });
const H1 = (t) => new Paragraph({ heading: H.HEADING_1, children: [R(t)] });
const H2 = (t) => new Paragraph({ heading: H.HEADING_2, children: [R(t)] });
const H3 = (t) => new Paragraph({ heading: H.HEADING_3, children: [R(t)] });
const bullet = (children) =>
  new Paragraph({
    numbering: { reference: "b", level: 0 },
    spacing: { after: 60 },
    children: typeof children === "string" ? [R(children)] : children,
  });

const thin = { style: BorderStyle.SINGLE, size: 1, color: "B7B7B7" };
const cellBorders = { top: thin, bottom: thin, left: thin, right: thin };
function cell(content, w, head = false) {
  let runs;
  if (Array.isArray(content)) runs = content;
  else
    runs = [
      new TextRun({
        text: String(content),
        bold: head,
        size: head ? 18 : 18,
        color: head ? "FFFFFF" : "1A1A1A",
      }),
    ];
  return new TableCell({
    width: { size: w, type: W },
    borders: cellBorders,
    shading: { fill: head ? "1F4E79" : "FFFFFF", type: ShadingType.CLEAR },
    margins: { top: 60, bottom: 60, left: 110, right: 110 },
    children: [new Paragraph({ spacing: { after: 0 }, children: runs })],
  });
}
const BC = (t) => [new TextRun({ text: t, bold: true, size: 18, color: "1A1A1A" })];
function table(rows, widths) {
  return new Table({
    width: { size: widths.reduce((a, b) => a + b, 0), type: W },
    columnWidths: widths,
    rows: rows.map(
      (r, ri) =>
        new TableRow({
          tableHeader: ri === 0,
          children: r.map((c, ci) => cell(c, widths[ci], ri === 0)),
        })
    ),
  });
}
// code box: single-cell light-gray table with monospace lines
function codeBox(lines) {
  return new Table({
    width: { size: CONTENT, type: W },
    columnWidths: [CONTENT],
    rows: [
      new TableRow({
        children: [
          new TableCell({
            width: { size: CONTENT, type: W },
            borders: cellBorders,
            shading: { fill: "F4F5F7", type: ShadingType.CLEAR },
            margins: { top: 100, bottom: 100, left: 160, right: 120 },
            children: lines.map(
              (ln) =>
                new Paragraph({
                  spacing: { after: 0 },
                  children: [
                    new TextRun({ text: ln || " ", font: "Consolas", size: 16 }),
                  ],
                })
            ),
          }),
        ],
      }),
    ],
  });
}
const rule = () =>
  new Paragraph({
    spacing: { after: 200 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: "DA291C", space: 1 } },
    children: [R("")],
  });

// ---------- content ----------
const children = [];

// Title block
children.push(
  new Paragraph({
    spacing: { before: 2400, after: 0 },
    alignment: AlignmentType.LEFT,
    children: [new TextRun({ text: "fwforge", bold: true, size: 64, color: "1F4E79" })],
  }),
  new Paragraph({
    spacing: { before: 120, after: 60 },
    children: [new TextRun({ text: "Palo Alto → FortiGate Conversion", bold: true, size: 34 })],
  }),
  new Paragraph({
    spacing: { after: 240 },
    children: [new TextRun({ text: "Capability overview and comparison with FortiConverter", size: 26, color: "555555" })],
  }),
  rule(),
  P([
    R("An open, clean-room PAN-OS → FortiOS converter. ", { italics: true }),
    R("Prepared for Fortinet engineering review · June 2026 · fwforge v0.52.2", { color: "555555" }),
  ]),
  new Paragraph({ children: [new PageBreak()] }),
);

// TOC
children.push(
  H1("Contents"),
  new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
  new Paragraph({ children: [new PageBreak()] }),
);

// 1. Executive summary
children.push(
  H1("1. Executive summary"),
  P([
    R("fwforge is a transparent, fully local tool that converts Palo Alto PAN-OS configurations — firewall XML, "),
    R("set", { font: "Consolas", size: 18 }),
    R("/display-set format, and Panorama exports — into clean, restorable FortiOS configuration. It exists to make migrating off Palo Alto and onto FortiGate fast, auditable, and trustworthy."),
  ]),
  bullet([B("Clean-room. "), R("It contains no Fortinet or FortiConverter code, and no licensed FortiGuard data files. It targets the public FortiOS CLI only.")]),
  bullet([B("An on-ramp to FortiGate. "), R("Every conversion is a Palo Alto estate moving onto FortiOS. The tool's purpose is to remove migration friction from that path.")]),
  bullet([B("Full security-profile coverage. "), R("App-ID (per-application signatures), URL filtering (FortiGuard categories + explicit URL lists), file blocking, antivirus, WildFire (→ FortiSandbox), and IPS (anti-spyware / vulnerability) all convert — every PAN security-profile type except Data Filtering — each schema-certified against the live target.")]),
  bullet([B("Parity on the core, ahead on assurance. "), R("It matches FortiConverter on objects / policy / NAT / routing / VPN, and now on App-ID granularity, and goes beyond it on output quality: every emitted config is schema-certified against the exact target firmware build, is deterministic and git-diffable, and carries per-line provenance back to the source line.")]),
  P([
    R("The conversions and signature data in this document were "),
    B("verified live against a FortiGate-601F running FortiOS 8.0.0 build0167"),
    R(" — the FortiGuard application-signature database, web categories, file types, and IPS filters were read from the device, and the emitted App-ID / web-filter / file-filter / antivirus / IPS / FortiSandbox output was schema-certified clean (0 unknown tables, 0 unknown attributes)."),
  ]),
);

// 2. Differentiators
children.push(
  H1("2. What makes it different"),
  P("These properties distinguish fwforge from a typical converter. They are the reasons the output can be trusted on a production cutover."),
  bullet([B("Mappings sourced from your own FortiGate. "), R("Per-application App-ID, FortiGuard web categories, file types and IPS filters come from the target device's own FortiGuard database — read live (one read-only API call), cached locally, refreshable on demand — not a bundled third-party table that drifts. A staleness warning fires when the cache ages.")]),
  bullet([B("Schema-certified output. "), R("Every section and attribute is validated against the exact target firmware's CLI schema, fetched live from the device (one read-only API call) or from cache. Unknown table = error; unknown attribute = warning. Nothing reaches a device unverified.")]),
  bullet([B("Deterministic and diffable. "), R("No timestamps, no random ordering. Re-running the same input yields byte-identical output, so a reviewer can diff two conversions in git and see exactly what changed.")]),
  bullet([B("Per-line provenance and a real report. "), R("Every converted object records its source file and line. Findings are a structured report (Markdown + JSON + HTML) with severity and location — not warnings buried as comments in the config. A non-zero exit code is returned on errors.")]),
  bullet([B("Version-delta awareness. "), R("fwforge compares source and target FortiOS versions and reports removed or introduced features, auto-fixed attribute/section renames, and silent default-flips — in both upgrade and downgrade directions.")]),
  bullet([B("Never silently broadens or drops. "), R("Anything it cannot faithfully convert is flagged, never approximated into something more permissive. For example, a custom udp/53 service is not collapsed onto the FortiOS built-in DNS service, which is tcp+udp/53.")]),
  bullet([B("Local and target-model aware. "), R("It runs as a single local package with no cloud dependency, and maps interfaces against the destination model's real port inventory (read from a backup or model table) using a FortiOS-style faceplate.")]),
);

// 3. Capability matrix
children.push(
  new Paragraph({ children: [new PageBreak()] }),
  H1("3. PAN-OS → FortiGate capability matrix"),
  P("Everything fwforge converts from a Palo Alto source. Anything outside this table is reported as a finding, not dropped silently."),
  table(
    [
      ["Domain", "What fwforge converts", "Notes"],
      [BC("Input formats"), "PAN-OS firewall XML and set / display-set format; Panorama exports", "One unified parser, auto-detected. Panorama template-merged running-configs handled."],
      [BC("Panorama & multi-vsys"), "Device-group selection; shared + pre/post rulebases merged in PAN evaluation order; optional template for network config; each vsys → its own FortiOS VDOM", "Cross-vsys references flagged."],
      [BC("Interfaces"), "Physical, aggregate (LAG), Layer-3 subinterfaces (VLAN), loopback, tunnel", "Mapped to the destination model's real ports via a faceplate UI with positional auto-guess; promote-a-port-to-LAG and “do not map” supported."],
      [BC("Aggregates / LAG"), "PAN aggregate-ethernet → FortiOS 802.3ad aggregate (type aggregate + member ports + lacp-mode)", "LACP mode read from source; emitted before the VLANs that ride it so the script loads in order."],
      [BC("Zones"), "PAN security zones → FortiOS zones", "Emitted with intrazone allow to preserve PAN's default same-zone behavior; flagged for tightening."],
      [BC("Addresses"), "host / subnet / range / FQDN; IPv4 and IPv6 (address6)", "Names sanitized to FortiOS limits with every reference remapped."],
      [BC("Address groups"), "Nested groups with single-family enforcement", "Mixed-family members handled per FortiOS rules."],
      [BC("Services"), "Custom TCP/UDP (port + source-port ranges), service groups, predefined service-http/https", "Mapped to FortiOS built-ins only on exact semantic match — never broadened."],
      [BC("App-ID"), "App-IDs → application-control with PER-APPLICATION signatures (matched to the FortiGuard app DB), category fallback for the rest; App-IDs → policy service (standard ports); application-groups flattened to leaves", "Signature-level when an app DB is present (verified live, ~3,300 sigs). App-IDs matching a FortiOS built-in service emit that named service."],
      [BC("URL filtering"), "PAN url-filtering → FortiOS webfilter: FortiGuard categories + custom URL lists (custom-url-category) → a webfilter urlfilter table for per-URL allow/block", "Category IDs verified live. PAN action → ftgd-wf action; URL with * → wildcard, else simple."],
      [BC("File blocking"), "PAN file-blocking profiles → FortiOS file-filter profiles", "File types verified live. PAN action → block / log-only / warning."],
      [BC("Antivirus"), "PAN antivirus/virus → FortiOS antivirus profile (per-protocol av-scan block / monitor / disable from the PAN decoders)", "FortiGuard AV engine + signatures do the scanning; per-protocol scan intent carried."],
      [BC("WildFire"), "PAN wildfire-analysis → FortiSandbox submission folded into the antivirus profile (analytics-db + per-protocol fortisandbox)", "Needs a device-level FortiSandbox appliance / Cloud (config system fortisandbox); flagged."],
      [BC("IPS"), "PAN anti-spyware + vulnerability → one FortiOS IPS sensor: severity-filter entries + exact CVE-filter entries, FortiGuard-recommended baseline (action default)", "Posture parity, not signature-for-signature — CVE is the exact cross-vendor key; per-threat exceptions flagged (see §6)."],
      [BC("SSL inspection"), "webfilter / file-filter / AV / IPS policies attached with the built-in certificate-inspection profile", "SNI-based; no CA rollout. Switch to deep-inspection for full HTTPS content control."],
      [BC("Security policies"), "PAN rules → FortiOS firewall policy: zones, addresses, services, action, logging, disable state, source/destination negation", "Per-rule selection (exclude rules); schedules flagged; application-default handled."],
      [BC("NAT"), "Source NAT (interface PAT) → policy NAT or central-snat-map; destination/static NAT → VIP (+ port-forward); subnet 1:1 DNAT → range VIP", "NAT mode selectable: policy or central."],
      [BC("Routing"), "Static routes (egress inferred when omitted); BGP (AS, router-id, neighbors, networks, redistribute); OSPF (areas, networks, passive); IPv6 routes", "The route table also drives policy dstintf inference (longest-prefix-match)."],
      [BC("IPsec VPN"), "Site-to-site → route-based phase1/phase2-interface + tunnel routes + bidirectional policies; IKE crypto, proposals, PFS, IKEv2", "Encrypted / exported PSKs detected → placeholder + error (never a silently broken secret)."],
      [BC("Output hygiene"), "Prune unreferenced objects (iterative); merge duplicate objects; split interface pairs; include/exclude rules", "Acts on the output, not just reports."],
      [BC("Output packaging"), "config-all.txt + per-branch script files; findings embedded as # comments", "Deterministic ordering; restore-safe."],
      [BC("FortiManager"), "Optional JSON-RPC import bundle: object creates + a policy package for an ADOM", ""],
      [BC("Assurance"), "Schema certification; version-delta scan; Markdown / JSON / HTML report; XML coverage map (% of source read)", "See §2 and §5."],
    ],
    [1700, 4060, 3600]
  ),
);

// 4. Security profiles
children.push(
  new Paragraph({ children: [new PageBreak()] }),
  H1("4. Security-profile conversion"),
  P("Every PAN security-profile type converts except Data Filtering. A rule's profile-setting (direct refs or a profile-group) resolves to the matching FortiOS UTM profiles, built lazily and deduplicated, and attached to the policy."),
  H2("Converted"),
  bullet([B("App-ID → Application Control (per-application). "), R("A rule's App-IDs map to specific FortiOS application signatures via the target's FortiGuard app DB (e.g. Facebook, Microsoft.Teams, Microsoft.365), with FortiGuard categories as the fallback for unmatched apps; in parallel the apps' standard ports fill the policy service. Application-groups expand to their leaf apps.")]),
  bullet([B("URL filtering → Web Filter. "), R("PAN url-filtering profiles become FortiGuard-category webfilter profiles (one PAN category can expand to several, e.g. alcohol-and-tobacco → Alcohol + Tobacco), and PAN custom-url-category URL lists become a FortiOS webfilter urlfilter table — per-URL allow/block (wildcard or simple) carried over.")]),
  bullet([B("File blocking → File Filter. "), R("PAN file-blocking → FortiOS file-filter; PAN file types map to FortiOS file types over HTTP/FTP/SMTP/IMAP/POP3/MAPI/CIFS/SSH.")]),
  bullet([B("Antivirus → Antivirus profile. "), R("PAN virus decoders map to per-protocol av-scan (block / monitor / disable). The FortiGuard engine and signatures do the scanning; the per-protocol scan intent is carried.")]),
  bullet([B("WildFire → FortiSandbox. "), R("A wildfire-analysis reference folds FortiSandbox submission into the rule's antivirus profile (analytics-db + per-protocol fortisandbox). Requires a FortiSandbox appliance or FortiSandbox Cloud (device-level), which the report flags.")]),
  bullet([B("Anti-Spyware + Vulnerability → IPS sensor. "), R("Merged into one FortiOS IPS sensor: severity rules become severity-filter entries (FortiGuard-recommended action as the baseline), and CVE-pinned rules become exact CVE-filter entries — the one real cross-vendor key (e.g. Log4Shell maps precisely). This is posture parity, not signature-for-signature; per-threat exceptions and DNS sinkhole are flagged (see §6).")]),
  bullet([B("SSL inspection. "), R("Policies carrying a web / file / AV / IPS profile attach the built-in certificate-inspection profile (SNI-based, no certificate rollout). Deep-inspection is recommended in the report for full HTTPS content control.")]),
  H2("Not converted"),
  P("Data Filtering (→ FortiOS DLP) is the only remaining PAN profile type; it is flagged per rule for manual configuration. PAN risk-level URL buckets (high/medium/low-risk) and any unmapped category, file type, or App-ID are likewise flagged — never silently dropped."),
);

// 5. Output quality
children.push(
  H1("5. Output quality and assurance"),
  bullet([B("Schema certification. "), R("The emitted CLI is parsed and checked table-by-table, attribute-by-attribute, against the target build's schema. In this review a full PAN→FortiGate conversion certified clean against a live 601F (FortiOS 8.0.0 build0167): 0 unknown tables, 0 unknown attributes.")]),
  bullet([B("Deterministic output. "), R("No timestamps or nondeterministic ordering, so successive runs diff cleanly.")]),
  bullet([B("Structured findings. "), R("Markdown, JSON, and HTML reports, each finding tagged with severity, area, and source file:line. The HTML report is print-to-PDF friendly for hand-off.")]),
  bullet([B("Coverage map. "), R("The parser reports the percentage of source values it read and flags any unread subtree, so reviewers can see what was and was not considered.")]),
);

// 6. Scope & limitations
children.push(
  H1("6. Scope and limitations (stated plainly)"),
  P("Engineers should know exactly where the tool stops. Each of these is surfaced in the report; nothing fails silently."),
  bullet([B("IPS is posture parity, not signature parity. "), R("There is no Palo Alto Threat-ID → FortiGuard-signature crosswalk — for any tool — so PAN anti-spyware / vulnerability profiles map at the severity + CVE level (with FortiGuard's recommended action as the baseline), not signature-for-signature. CVE-pinned rules map exactly; per-threat exceptions and DNS sinkhole are flagged for manual review. Validate IPS before enforcing.")]),
  bullet([B("App-ID DB freshness. "), R("Per-application App-ID uses the target FortiGate's FortiGuard signature DB, cached locally; conversions are deterministic and offline and do not refetch per run. FortiGuard adds App-IDs continuously, so the tool warns when the cache is stale — refresh with one read-only call.")]),
  bullet([B("Data Filtering → DLP. "), R("The only PAN security-profile type not yet converted; flagged per rule. FortiOS ships the building blocks (DLP profiles + def-cc / def-ssn dictionaries) so this is a planned addition.")]),
  bullet([B("FortiSandbox is a device dependency. "), R("WildFire conversion enables FortiSandbox submission in the AV profile, but a FortiSandbox appliance or Cloud must be configured device-level (config system fortisandbox) — outside the converted policy package.")]),
  bullet([B("Complex NAT. "), R("Common source and destination NAT convert; exotic twice-NAT idioms are flagged for manual handling.")]),
  bullet([B("Remote-access VPN. "), R("Site-to-site IPsec converts; GlobalProtect / remote-access is not converted.")]),
);

// 7. Comparison
children.push(
  new Paragraph({ children: [new PageBreak()] }),
  H1("7. fwforge vs FortiConverter"),
  P("A feature-and-quality comparison for the Palo Alto → FortiGate path. Both tools convert the core object/policy/NAT/routing model; the differences are in coverage, granularity, and output assurance."),
  table(
    [
      ["Dimension", "fwforge", "FortiConverter"],
      [BC("Source coverage"), "Palo Alto (XML, set, Panorama, multi-vsys)", "Palo Alto plus 15+ other vendors — broader"],
      [BC("App-ID granularity"), "Per-application signatures from the target's own FortiGuard DB (live, refreshable) + category fallback", "Per-application signatures from a bundled licensed table"],
      [BC("Security profiles"), "App-ID, URL (categories + URL lists), file, AV, WildFire→FortiSandbox, IPS — schema-certified; DLP pending", "Broad profile coverage incl. DLP"],
      [BC("IPS conversion"), "Severity + exact CVE crosswalk + FortiGuard-recommended baseline; posture-parity, stated plainly", "No PA Threat-ID → FortiGuard signature crosswalk exists for either tool"],
      [BC("Output validation"), "Schema-certified against the exact target firmware build", "Not certified against the live target schema"],
      [BC("Determinism"), "Byte-deterministic, git-diffable", "Not deterministic"],
      [BC("Provenance / findings"), "Per-line source provenance; md/JSON/HTML report; non-zero exit on error", "Warnings as comments in config-all.txt"],
      [BC("Version-delta scan"), "Yes — bidirectional feature / rename / default-flip", "No"],
      [BC("Object hygiene"), "Prunes, merges, dedups (acts on output)", "Reports; discard is opt-in"],
      [BC("Routing-aware dstintf"), "Longest-prefix-match from source routes", "Falls back to any when missing (per docs)"],
      [BC("Deployment"), "Single local package, fully offline", "Heavier install; FGT→FGT path runs in cloud"],
      [BC("FortiManager output"), "JSON-RPC import bundle (objects + package)", "Yes — mature"],
      [BC("Support model"), "Self-hosted / community", "Official Fortinet support + service SLA"],
    ],
    [2560, 3520, 3280]
  ),
  P([
    B("Where FortiConverter leads: "),
    R("vendor breadth, Data Filtering → DLP today, official support, and product maturity. "),
    B("Where fwforge leads: "),
    R("output assurance (schema certification against the exact build), transparency, determinism, per-line provenance, version-delta awareness, active hygiene, fully-local operation, and App-ID / profile mappings sourced live from your own FortiGate rather than a bundled table."),
  ]),
);

// 8. Example output
children.push(
  H1("8. Example output"),
  P("An emitted, schema-certified excerpt showing per-application App-ID signatures, the IPS CVE crosswalk, and a policy carrying the full UTM stack:"),
  codeBox([
    "config application list",
    "    edit \"pan-appctrl-1\"",
    "        set other-application-action block",
    "        config entries",
    "            edit 1",
    "                set application 15832 15817 37065   # Facebook, Gmail, Zoom",
    "                set action pass",
    "            next",
    "        end",
    "    next",
    "end",
    "",
    "config ips sensor",
    "    edit \"ips-vuln-strict-spy-strict\"",
    "        config entries",
    "            edit 1",
    "                set severity critical high",
    "                set action reset",
    "            next",
    "            edit 2",
    "                set cve CVE-2021-44228          # Log4Shell — exact cross-vendor match",
    "                set action reset",
    "            next",
    "        end",
    "    next",
    "end",
    "",
    "config firewall policy",
    "    edit 1",
    "        set name \"trust-to-untrust\"",
    "        set utm-status enable",
    "        set ssl-ssh-profile \"certificate-inspection\"",
    "        set application-list \"pan-appctrl-1\"",
    "        set ips-sensor \"ips-vuln-strict-spy-strict\"",
    "        set av-profile \"av-av1-wf\"            # av-scan + FortiSandbox",
    "        set webfilter-profile \"wf-url-strict\"",
    "    next",
    "end",
  ]),
);

// Appendix
children.push(
  H1("Appendix: verification methodology"),
  P("To keep category and type mappings honest, fwforge's PAN-OS conversion data was verified against a live FortiGate rather than from documentation alone:"),
  bullet([B("The FortiGuard application-signature DB "), R("(~3,300 signatures with their IDs) was read from the device at /api/v2/cmdb/application/name — this drives per-application App-ID.")]),
  bullet([B("FortiGuard web categories "), R("(the ~93 IDs used by URL-filtering) were read from /api/v2/monitor/webfilter/fortiguard-categories; file-filter file types from the antivirus.filetype data source.")]),
  bullet([B("IPS sensor filters, antivirus av-scan / fortisandbox enums, and webfilter urlfilter types "), R("were taken from the device's CLI schema, so emitted severity / CVE / action tokens are valid for that exact build.")]),
  bullet([B("The emitted configuration "), R("(App-ID, web-filter + urlfilter, file-filter, antivirus + FortiSandbox, IPS, interfaces and policies) was run through fwforge's own schema certifier against the device's CLI schema and returned 0 unknown tables and 0 unknown attributes.")]),
  P([R("Reference device: FortiGate-601F, FortiOS 8.0.0 build0167.", { italics: true, color: "555555" })]),
);

// ---------- document ----------
const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 30, bold: true, font: "Arial", color: "1F4E79" },
        paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 25, bold: true, font: "Arial", color: "2E2E2E" },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, font: "Arial", color: "2E2E2E" },
        paragraph: { spacing: { before: 140, after: 80 }, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      { reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•",
        alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 460, hanging: 240 } } } }] },
    ],
  },
  sections: [
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
        },
      },
      footers: {
        default: new Footer({
          children: [
            new Paragraph({
              tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
              children: [
                new TextRun({ text: "fwforge — Palo Alto → FortiGate", size: 16, color: "888888" }),
                new TextRun({ text: "\t", size: 16 }),
                new TextRun({ children: ["Page ", PageNumber.CURRENT], size: 16, color: "888888" }),
              ],
            }),
          ],
        }),
      },
      children,
    },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync("fwforge_PaloAlto_to_FortiGate.docx", buf);
  console.log("wrote fwforge_PaloAlto_to_FortiGate.docx", buf.length, "bytes");
});
