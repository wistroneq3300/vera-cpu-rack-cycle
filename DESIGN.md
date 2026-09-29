---
name: Vera CPU Rack Cycle
description: Wistron-inspired offline engineering review with readable findings and traceable evidence.
colors:
  brand: "#006b49"
  brand-dark: "#064b38"
  ink: "#182c32"
  muted: "#52656c"
  line: "#d5dfdf"
  paper: "#fff"
  canvas: "#f2f5f4"
  fail: "#9d2929"
  fail-bg: "#fff0ee"
  warn: "#815400"
  warn-bg: "#fff5d8"
  ok-bg: "#e4f3eb"
  focus: "#00815b"
  badge-neutral-bg: "#e8edef"
  badge-neutral-ink: "#34484f"
  known-bg: "#e8eef8"
  known-ink: "#365272"
  new-ink: "#963832"
  table-bg: "#f3f6f5"
  tab-hover: "#e4ece8"
  disclosure-hover: "#f5f8f6"
typography:
  headline:
    fontFamily: '"Segoe UI", Arial, sans-serif'
    fontSize: "34px"
    fontWeight: 650
    lineHeight: 1.15
    letterSpacing: "-.025em"
  title:
    fontFamily: '"Segoe UI", Arial, sans-serif'
    fontSize: "23px"
    fontWeight: 650
    lineHeight: 1.3
  body:
    fontFamily: '"Segoe UI", Arial, sans-serif'
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: '"Segoe UI", Arial, sans-serif'
    fontSize: "12px"
    fontWeight: 700
    lineHeight: 1.6
    letterSpacing: ".025em"
  mono:
    fontFamily: 'Consolas, "Liberation Mono", monospace'
    fontSize: "13px"
rounded:
  surface: "6px"
  badge: "4px"
  tab: "0"
spacing:
  compact: "4px"
  small: "8px"
  related: "12px"
  medium: "16px"
  control-group: "18px"
  section: "24px"
  sheet: "26px"
components:
  button:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.surface}"
    padding: "9px 13px"
  button-hover:
    backgroundColor: "{colors.ok-bg}"
  input:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.surface}"
    padding: "9px 13px"
    width: "280px"
  select:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.surface}"
    padding: "9px 13px"
  tab:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.tab}"
    padding: "12px 18px"
  tab-selected:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.brand-dark}"
  tab-hover:
    backgroundColor: "{colors.tab-hover}"
  badge:
    backgroundColor: "{colors.badge-neutral-bg}"
    textColor: "{colors.badge-neutral-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.badge}"
    padding: "3px 8px"
  badge-fail:
    backgroundColor: "{colors.fail-bg}"
    textColor: "{colors.fail}"
  badge-warn:
    backgroundColor: "{colors.warn-bg}"
    textColor: "{colors.warn}"
  badge-pass:
    backgroundColor: "{colors.ok-bg}"
    textColor: "{colors.brand-dark}"
  badge-known:
    backgroundColor: "{colors.known-bg}"
    textColor: "{colors.known-ink}"
  badge-new:
    backgroundColor: "{colors.fail-bg}"
    textColor: "{colors.new-ink}"
  sheet:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.surface}"
    padding: "26px"
  disclosure:
    textColor: "{colors.ink}"
    padding: "17px 4px"
---

# Design System: Vera CPU Rack Cycle

## Overview

**Creative North Star: "The Engineering Worksheet"**

This system expresses the approved Wistron-inspired engineering direction through restrained green accents, light laboratory worksheet surfaces and readable evidence. It is an internal report identity, not a claim to reproduce an official Wistron brand specification or logo.

Quiet, flat containers let factual results carry the visual weight. System fonts and locally embedded styles keep long reviews readable without network access. The implemented source is `report.css`, `report.js` and `cycle_report.py`; the Operate surface composition and review sequence live in `report_direction.md`.

**Key Characteristics:**

- Restrained green identity with light, bordered worksheets.
- Readable system typography and tabular numerals.
- Explicit status text with separate health and execution labels.
- Native disclosures and local evidence links.

## Colors

### Primary

Brand green identifies links and selected navigation. Deep brand green anchors the header and positive-state text. The green focus color is an interaction cue. These observed colors are Wistron-inspired, not certified brand values.

### Neutral

Ink and muted text establish hierarchy on paper sheets and the pale canvas. Line separates facts, table rows and disclosures. Table and hover surfaces provide subtle state distinctions without depth effects.

### Semantic states

Failure foreground and background identify FAIL, BLOCKED and INCOMPLETE. Amber supports WARN, PENDING and RUNNING. Positive green supports PASS and COMPLETE. The neutral badge is the fallback for other status strings. Blue KNOWN and warm NEW describe classification independently of severity.

**The Explicit Status Rule.** Always retain written status labels; color alone cannot communicate a result. Health, execution completeness and known/new classification remain separate concepts.

## Typography

Segoe UI with Arial and sans-serif fallbacks is intentional: familiar system text supports dense engineering reading and works offline. Consolas with Liberation Mono and monospace fallbacks identifies run IDs, paths and raw evidence. No font files or remote font service are required.

The headline, title, body and badge-label roles are recorded above. Subsection headings are compact bold text (17px, line-height 1.4); supporting metadata uses smaller text (13px). Numeric text uses tabular figures. Paragraphs are capped at a readable measure (75ch). The hierarchy is role-based rather than a mathematical type scale.

**The Readable Evidence Rule.** Preserve wrap opportunities for long IDs and paths, and keep raw evidence visually distinct from the human-readable summary.

## Layout

The outer header, main and footer share a centered maximum width (1376px) with horizontal gutters (28px). Worksheets separate sections with space (24px) and contain their own dense material. Flexible facts and outcome groups wrap without imposing fixed column counts. Tables scroll within their own width-constrained wrapper. Horizontal tab overflow stays inside navigation.

At the observed narrow breakpoint (700px), outer gutters reduce (16px), the headline becomes smaller (29px), body text becomes smaller (14px), and worksheet padding contracts (18px 14px). Evidence lists move from two columns to one, filter search expands to available width, and disclosure metadata moves below its title. This preserves the same reading order on a phone.

Print hides navigation and filter controls, shows every report panel, and removes sheet borders. The Print report action temporarily expands disclosures and restores their prior open states after printing.

## Elevation & Depth

There are no shadows or elevation effects. Paper, canvas, thin borders and subtle hover backgrounds establish separation. Interactions change state immediately; there are no transitions or animations to suppress for reduced-motion preferences.

**The Flat Worksheet Rule.** Keep report sections flat and use the established surface and divider vocabulary to group evidence.

## Shapes

Worksheets and ordinary controls share gently curved corners through the surface radius. Badges use the smaller badge radius. Tabs are square: the final stylesheet rule overrides the earlier rounded tab declaration. Thin solid borders (1px) define controls and sections; the selected tab uses a stronger bottom rule (3px).

## Components

### Buttons and fields

Print is the ordinary bordered paper button. Its hover uses the positive background; it has no distinct pressed or disabled styling. Search and native selects share the same surface, border and radius. Search has a visible label; placeholders do not replace labels. The filter count is a polite live region, and no matching issues produces an explicit empty state.

All interactive elements receive the shared visible keyboard outline (3px, offset 3px). Links retain underlining and darken on hover. No special input hover state is defined in the implementation.

### Navigation

Tabs use a paper selected surface, deep green text and a green bottom rule. Selection is also exposed with `aria-selected`, paired `aria-controls`/`aria-labelledby` relationships and roving tab stops. Left/Right arrows move among tabs; Home/End select the first/last tab. Tab changes preserve open disclosures. A skip link appears on keyboard focus.

### Badges and worksheets

Small text badges carry severity, execution state and classification. The outcome renders Health and Execution as separately labeled values. Worksheet sheets use paper, the shared border and surface radius; tabular facts remain unembellished. There are no decorative charts or telemetry animations.

### Evidence disclosures

Native `details` and `summary` retain their platform keyboard behavior and disclosure marker. Hover softly highlights the summary. PRE, loop history and recurring issues expand into structured findings, actions, identities and original evidence. An occurrence link selects the owning node panel and opens its phase disclosure.

### Offline and fallback states

CSS and JavaScript are embedded in the generated HTML. Evidence links are relative to the campaign bundle, open separately and require the HTML to remain with its evidence folders. Invalid or absent evidence paths render “Evidence unavailable”; this label does not assert that a valid linked file exists. No remote assets, tracking or fonts are required.

Before JavaScript runs, all report panels remain visible in document order and native disclosures still work. The script adds tab switching and filtering. Generated Markdown, text summaries and JSON records provide additional offline representations. These fallbacks preserve findings rather than implying a successful run when evidence is missing.

## Do's and Don'ts

### Do:

- **Do** use the extracted colors and visible text labels for status.
- **Do** keep health and execution completeness separately labeled.
- **Do** retain keyboard focus, native disclosure behavior and contained table scrolling.
- **Do** keep the report and its evidence folders together for offline review.

### Don't:

- **Don't** present KNOWN classification as a pass exemption.
- **Don't** introduce remote fonts or assets into the offline report.
- **Don't** claim these inspired colors or the text header are an official brand specification.
- **Don't** replace recorded findings with decorative or unmeasured charts.
