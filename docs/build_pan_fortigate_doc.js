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
    R("Prepared for Fortinet engineering review · June 2026 · fwforge v0.49.0", { color: "555555" }),
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
  bullet([B("Parity on the core, ahead on assurance. "), R("It matches FortiConverter on the object / policy / NAT / routing / VPN conversion, and goes beyond it on output quality: every emitted config is schema-certified against the exact target firmware build, is deterministic and git-diffable, and carries per-line provenance back to the source line.")]),
  P([
    R("The conversions and category data in this document were "),
    B("verified live against a FortiGate-601F running FortiOS 8.0.0 build0167"),
    R(" — FortiGuard web categories and file types were read from the device, and the emitted output was schema-certified clean (0 unknown tables, 0 unknown attributes)."),
  ]),
);

// 2. Differentiators
children.push(
  H1("2. What makes it different"),
  P("Six properties distinguish fwforge from a typical converter. They are the reasons the output can be trusted on a production cutover."),
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
      [BC("App-ID"), "App-IDs → application-control category profiles; App-IDs → policy service (standard ports); application-groups flattened to leaves", "Category-level (see §6). App-IDs that match a FortiOS built-in service are emitted as that named service."],
      [BC("URL filtering"), "PAN url-filtering profiles → FortiOS webfilter (FortiGuard category) profiles", "Category IDs verified live. PAN action → ftgd-wf action (block; alert→monitor; continue→warning; override→authenticate)."],
      [BC("File blocking"), "PAN file-blocking profiles → FortiOS file-filter profiles", "File types verified live. PAN action → block / log-only / warning."],
      [BC("SSL inspection"), "webfilter / file-filter policies attached with the built-in certificate-inspection profile", "SNI-based; no CA rollout. Switch to deep-inspection for full HTTPS content control."],
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
  P("PAN security profiles split into two groups: those that are category- or type-level (faithfully convertible in a clean-room tool) and those that are signature/engine-level (which are flagged, not guessed)."),
  H2("Converted"),
  bullet([B("App-ID → Application Control. "), R("A rule's App-IDs become a FortiOS application-control profile (FortiGuard categories) and, in parallel, a port-based service from the apps' standard ports — so the policy is both port-based and app-aware. Application-groups are expanded to their leaf apps.")]),
  bullet([B("URL filtering → Web Filter. "), R("Each PAN url-filtering profile becomes a FortiOS FortiGuard-category webfilter profile. PAN per-category actions map to ftgd-wf actions; one PAN category can expand to several FortiGuard categories (e.g. alcohol-and-tobacco → Alcohol + Tobacco). Profiles are deduplicated and attached to every policy that referenced them.")]),
  bullet([B("File blocking → File Filter. "), R("Each PAN file-blocking profile becomes a FortiOS file-filter profile; PAN file types map to FortiOS file types over HTTP/FTP/SMTP/IMAP/POP3/MAPI/CIFS/SSH.")]),
  bullet([B("SSL inspection. "), R("Policies carrying a web or file profile are attached to the built-in certificate-inspection profile (SNI-based, no certificate rollout). Deep-inspection is recommended in the report for full HTTPS content control.")]),
  H2("Flagged, not converted (by design)"),
  P("Antivirus, Anti-Spyware, Vulnerability Protection, WildFire, and Data Filtering are signature/engine-level and are reported per rule for manual attachment rather than approximated. PAN risk-level URL buckets (high/medium/low-risk) and any unmapped category or file type are likewise flagged — never silently dropped."),
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
  bullet([B("Category-level App-ID and URL mapping. "), R("fwforge maps to FortiOS application-control and FortiGuard web categories, not per-application or per-URL signatures. The PAN-app → FortiGuard-signature-ID table is licensed and cannot be used in a clean-room tool, so this is coarser than FortiConverter's licensed mapping. With a Fortinet-sanctioned mapping, fwforge could emit signature-level profiles — a natural collaboration point.")]),
  bullet([B("Engine-level profiles. "), R("Antivirus, IPS (Anti-Spyware / Vulnerability), WildFire, and Data Filtering are not converted (see §4).")]),
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
      [BC("App-ID / URL granularity"), "Category-level (public IDs, clean-room)", "Signature-level (licensed FortiGuard table) — finer"],
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
    R("vendor breadth, signature-level App-ID/URL mapping, official support, and product maturity. "),
    B("Where fwforge leads: "),
    R("output assurance (schema certification), transparency, determinism, provenance, version-delta awareness, active hygiene, and fully-local operation."),
  ]),
);

// 8. Example output
children.push(
  H1("8. Example output"),
  P("A PAN physical port carrying VLANs, promoted to a LAG, with a url-filtering profile — as emitted (and schema-certified clean) by fwforge:"),
  codeBox([
    "config system interface",
    "    edit \"lag-uplink\"",
    "        set type aggregate",
    "        set member \"port5\" \"port6\"",
    "        set lacp-mode active",
    "    next",
    "    edit \"vlan100\"",
    "        set type vlan",
    "        set interface \"lag-uplink\"      # rides the LAG; emitted after it",
    "        set vlanid 100",
    "    next",
    "end",
    "",
    "config webfilter profile",
    "    edit \"wf-url-strict\"",
    "        config ftgd-wf",
    "            config filters",
    "                edit 1",
    "                    set category 26       # Malicious Websites",
    "                    set action block",
    "                next",
    "            end",
    "        end",
    "    next",
    "end",
    "",
    "config firewall policy",
    "    edit 1",
    "        set name \"trust-to-untrust\"",
    "        set utm-status enable",
    "        set ssl-ssh-profile \"certificate-inspection\"",
    "        set webfilter-profile \"wf-url-strict\"",
    "    next",
    "end",
  ]),
);

// Appendix
children.push(
  H1("Appendix: verification methodology"),
  P("To keep category and type mappings honest, fwforge's PAN-OS conversion data was verified against a live FortiGate rather than from documentation alone:"),
  bullet([B("FortiGuard web categories "), R("(the ~93 IDs used by URL-filtering) were read from the device at /api/v2/monitor/webfilter/fortiguard-categories.")]),
  bullet([B("File-filter file types "), R("were read from the device's antivirus.filetype data source.")]),
  bullet([B("The emitted configuration "), R("was run through fwforge's own schema certifier against the device's CLI schema and returned 0 unknown tables and 0 unknown attributes.")]),
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
