//! hacienda-backend#5 — the zero-raw-bytes corpus acceptance harness (epic gate).
//!
//! Synthetic-PII-only fixtures (planted, obviously fake values, per gaze's own
//! fixture discipline: no real PII in the repo). Office fixtures are built
//! in-code as minimal valid OOXML zip packages; the PDF is emitted byte-precise
//! with a computed xref. Assertions name the fixture, the planted span, and the
//! leaking class on failure.
//!
//! **Class-coverage note**: the no-network core floor + the `secrets` rulepack
//! detect email, credit_card, iban, ip_address, phone, ssn, security_token,
//! password. Person *names* are NER(`ort`)-backed — gaze publishes its NER
//! model files nowhere and this harness runs no network/model setup, so names
//! are out of scope here and tracked for epic 2 (policy/model workstream).
//! The registry is process-global; phases serialize like `tests/registration.rs`.

use std::io::Write as _;
use std::sync::OnceLock;

use xberg::{ChunkingConfig, ExtractInput, ExtractionConfig};

use hacienda_backend::{GazeEngine, GazeRedactor};

// ---------------------------------------------------------------------------
// Planted corpus — every value obviously fake (synthetic only).
// ---------------------------------------------------------------------------

const EMAIL: &str = "jane.roe@example.com";
const EMAIL_LABEL: &str = "EMAIL";
const IBAN: &str = "AT61 1904 3002 3457 3201";
const IBAN_LABEL: &str = "IBAN";
const CARD: &str = "4111 1111 1111 1111";
const CARD_LABEL: &str = "CREDIT_CARD";
const IP: &str = "10.1.2.3";
const IP_LABEL: &str = "IP_ADDRESS";
const PHONE: &str = "+1 212 555 0100";
const PHONE_LABEL: &str = "PHONE";
const SSN: &str = "SSN 536-90-4399";
const SSN_LABEL: &str = "SSN";
/// Canadian SIN-like (3-3-3 synthetic format).
const TOKEN: &str = "AKIAQQQQTESTEXAMPLE0";
const TOKEN_LABEL: &str = "SECURITY_TOKEN";
/// password.field fires line-anchored; only the VALUE span is the finding.
const PASSWORD: &str = "synthetic77-qq-passphrase";
const PASSWORD_LABEL: &str = "PASSWORD";

/// PII-free filler so multi-chunk fixtures chunk deterministically.
const FILLER: &str = "Filler line: lorem ipsum tessellates quietly. ";

// ---------------------------------------------------------------------------
// Fixture builders (minimal, valid OOXML package shapes).
// ---------------------------------------------------------------------------

fn zip_bytes(entries: &[(&str, String)]) -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut buffer);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in entries {
        writer.start_file(*name, options).expect("zip entry");
        writer.write_all(content.as_bytes()).expect("zip write");
    }
    writer.finish().expect("zip finish");
    buffer.into_inner()
}

fn content_types(overrides: &[(&str, &str)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
         <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
         <Default Extension=\"xml\" ContentType=\"application/xml\"/>",
    );
    for (part, content_type) in overrides {
        xml.push_str(&format!(
            "<Override PartName=\"{part}\" ContentType=\"{content_type}\"/>"
        ));
    }
    xml.push_str("</Types>");
    xml
}

fn root_rels(doc: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"{doc}\"/>\
         </Relationships>"
    )
}

fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn docx_fixture(paragraph: &str) -> Vec<u8> {
    zip_bytes(&[
        (
            "[Content_Types].xml",
            content_types(&[(
                "/word/document.xml",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            )]),
        ),
        ("_rels/.rels", root_rels("word/document.xml")),
        (
            "word/document.xml",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
                 <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
                 <w:body><w:p><w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p></w:body></w:document>",
                xml_escape(paragraph)
            ),
        ),
    ])
}

fn xlsx_fixture(cells: &[&str]) -> Vec<u8> {
    let mut row = String::from("<row r=\"1\">");
    for (index, cell) in cells.iter().enumerate() {
        row.push_str(&format!(
            "<c r=\"{}1\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
            char::from_u32(u32::try_from(index).expect("cols") + 65).expect("col letter"),
            xml_escape(cell)
        ));
    }
    row.push_str("</row>");
    zip_bytes(&[
        (
            "[Content_Types].xml",
            content_types(&[
                (
                    "/xl/workbook.xml",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
                ),
                (
                    "/xl/worksheets/sheet1.xml",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
                ),
            ]),
        ),
        ("_rels/.rels", root_rels("xl/workbook.xml")),
        (
            "xl/workbook.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" \
             xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">\
             <sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>"
                .to_owned(),
        ),
        (
            "xl/_rels/workbook.xml.rels",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
             <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
             </Relationships>"
                .to_owned(),
        ),
        ("xl/worksheets/sheet1.xml", format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
             <sheetData>{row}</sheetData></worksheet>"
        )),
    ])
}

fn pptx_fixture(slide_text: &str) -> Vec<u8> {
    zip_bytes(&[
        (
            "[Content_Types].xml",
            content_types(&[
                (
                    "/ppt/presentation.xml",
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
                ),
                (
                    "/ppt/slides/slide1.xml",
                    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
                ),
            ]),
        ),
        ("_rels/.rels", root_rels("ppt/presentation.xml")),
        (
            "ppt/presentation.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" \
             xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">\
             <p:sldIdLst><p:sldId id=\"256\" r:id=\"rId1\"/></p:sldIdLst>\
             <p:sldSz cx=\"12192000\" cy=\"6858000\"/></p:presentation>"
                .to_owned(),
        ),
        (
            "ppt/_rels/presentation.xml.rels",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
             <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide\" Target=\"slides/slide1.xml\"/>\
             </Relationships>"
                .to_owned(),
        ),
        ("ppt/slides/slide1.xml", format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <p:sld xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" \
             xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\">\
             <p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/>\
             <p:cNvGrpSpPr/><p:grpSpPr/></p:nvGrpSpPr>\
             <p:grpSpPr/><p:sp><p:txBody><a:p><a:r><a:t xml:space=\"preserve\">{}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>",
            xml_escape(slide_text)
        )),
    ])
}

/// Minimal byte-precise PDF 1.4 (computed xref; ASCII-only payloads keep the
/// offset math trivial).
fn pdf_fixture(text: &str) -> Vec<u8> {
    let stream = format!("BT /F1 12 Tf 72 720 Td ({}) Tj ET", xml_escape(text));
    let objects: [String; 5] = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_owned(),
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".to_owned(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
            .to_owned(),
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".to_owned(),
        format!(
            "5 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            stream.len(),
            stream
        ),
    ];

    let mut body = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for object in &objects {
        offsets.push(body.len());
        body.push_str(object);
    }

    let xref_offset = body.len();
    let mut xref = format!("xref\n0 {}\n", offsets.len() + 1);
    xref.push_str("0000000000 65535 f \n");
    for offset in &offsets {
        xref.push_str(&format!("{offset:010} 00000 n \n"));
    }
    xref.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
        offsets.len() + 1
    ));
    body.push_str(&xref);
    body.into_bytes()
}

// ---------------------------------------------------------------------------
// Extraction harness.
// ---------------------------------------------------------------------------

fn seq() -> &'static tokio::sync::Mutex<()> {
    static SEQ: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SEQ.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn cleanup() {
    let _ = xberg::plugins::unregister_post_processor("redaction");
}

/// Force chunking so the zero-raw gate covers chunks too.
fn harness_config() -> ExtractionConfig {
    ExtractionConfig {
        chunking: Some(ChunkingConfig {
            // Small chunks force many chunk boundaries so the zero-raw gate
            // and the ADR-0002 byte-range rule are exercised heavily.
            // NOTE: max_overlap must stay below max_characters (xberg
            // validates this eagerly).
            max_characters: 128,
            // xberg validates max_overlap < max_characters eagerly; the
            // default 200 violates it at 128.
            overlap: 24,
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The gate: no planted raw value in the redacted content or any chunk.
/// Failure messages name the fixture, the planted span (offset in the plant
/// string serves), and the leaking class.
fn assert_zero_raw_leak(fixture: &str, doc: &xberg::ExtractedDocument, plants: &[(&str, &str)]) {
    for (class, raw) in plants {
        assert!(
            !doc.content.contains(raw),
            "ZERO-RAW GATE: fixture {fixture:?} leaks {class:?} raw {raw:?} in content {:?}",
            doc.content
        );
        let chunks = doc.chunks.as_deref().unwrap_or(&[]);
        for (index, chunk) in chunks.iter().enumerate() {
            assert!(
                !chunk.content.contains(raw),
                "ZERO-RAW GATE: fixture {fixture:?} chunk #{index} leaks {class:?} raw {raw:?}: {:?}",
                chunk.content
            );
            // ADR-0002 token-length rule: chunk ranges refer to the rewritten
            // content, not the original.
            assert!(
                chunk.metadata.byte_end <= doc.content.len()
                    && chunk.metadata.byte_start < chunk.metadata.byte_end,
                "CHUNK RANGE: fixture {fixture:?} chunk #{index} range {}..{} invalid against \
                 rewritten content (len {})",
                chunk.metadata.byte_start,
                chunk.metadata.byte_end,
                doc.content.len()
            );
        }
    }
}

/// `[TYPE_N]` tokens present for every expected label, ordinals contiguous
/// from 1 (consistent per class — no gaps, no post-hoc renames).
fn assert_tokens_present(fixture: &str, content: &str, labels: &[&str]) {
    let tokens = scan_tokens(content);
    for label in labels {
        let ordinals: Vec<u32> = tokens
            .iter()
            .filter(|(token_label, _)| token_label == label)
            .map(|(_, ordinal)| *ordinal)
            .collect();
        assert!(
            !ordinals.is_empty(),
            "TOKEN MISSING: fixture {fixture:?} has no [{label}_N] token; content {content:?}; tokens {tokens:?}"
        );
        for wanted in 1..=ordinals.len() as u32 {
            assert!(
                ordinals.contains(&wanted),
                "TOKEN CONSISTENCY: fixture {fixture:?} label {label:?} ordinals {ordinals:?} missing {wanted}"
            );
        }
    }
}

fn scan_tokens(content: &str) -> Vec<(String, u32)> {
    let mut tokens = Vec::new();
    for part in content.split([' ', ',', '.', '\n', '\t', ';', ':']) {
        let part = part.trim();
        let Some(inner) = part.strip_prefix('[').and_then(|p| p.strip_suffix(']')) else {
            continue;
        };
        let Some((label, ordinal)) = inner.rsplit_once('_') else {
            continue;
        };
        if label.is_empty() || !label.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            continue;
        }
        if ordinal.is_empty() || !ordinal.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(ordinal) = ordinal.parse() {
            tokens.push((label.to_owned(), ordinal));
        }
    }
    tokens
}

fn text_input(body: &str, filename: &str) -> ExtractInput {
    ExtractInput::from_bytes(body.as_bytes(), "text/plain", Some(filename.to_owned()))
}

/// Extract with the composed pipeline: installs the passed engine under the
/// same-name seam, then runs the full `extract` with forced chunking.
async fn extract_installed(engine: GazeEngine, input: ExtractInput) -> xberg::ExtractionResult {
    GazeRedactor::install(engine).expect("install must succeed");
    xberg::core::extract::extract(input, &harness_config())
        .await
        .expect("extraction must succeed")
}

async fn extract_docx(paragraph: &str, filename: &str) -> xberg::ExtractionResult {
    extract_installed(
        engine_with_secrets().await,
        ExtractInput::from_bytes(
            docx_fixture(paragraph),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            Some(filename.to_owned()),
        ),
    )
    .await
}

async fn extract_xlsx(cells: &[&str], filename: &str) -> xberg::ExtractionResult {
    extract_installed(
        engine_with_secrets().await,
        ExtractInput::from_bytes(
            xlsx_fixture(cells),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            Some(filename.to_owned()),
        ),
    )
    .await
}

async fn extract_pptx(slide: &str, filename: &str) -> xberg::ExtractionResult {
    extract_installed(
        engine_with_secrets().await,
        ExtractInput::from_bytes(
            pptx_fixture(slide),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            Some(filename.to_owned()),
        ),
    )
    .await
}

async fn extract_txt(body: &str, filename: &str) -> xberg::ExtractionResult {
    extract_installed(engine_with_secrets().await, text_input(body, filename)).await
}

/// Core floor + the `secrets` rulepack (credential classes, spec §2).
async fn engine_with_secrets() -> GazeEngine {
    GazeEngine::core_floor_with(&["secrets"]).expect("core+secrets pipeline must build")
}

async fn install_gate() {
    GazeRedactor::install(engine_with_secrets().await).expect("install must succeed");
}

// ---------------------------------------------------------------------------
// Fixture phases — each .docx/.xlsx/.pptx/.pdf/.txt goes through full extract.
// ---------------------------------------------------------------------------

/// docx #1: email + IBAN + phone one paragraph.
#[tokio::test]
async fn corpus_docx_a() {
    let _guard = seq().lock().await;
    cleanup().await;
    install_gate().await;

    let plants = [
        (EMAIL_LABEL, EMAIL),
        (IBAN_LABEL, IBAN),
        (PHONE_LABEL, PHONE),
    ];
    let body = format!(
        "Quarterly note for {EMAIL} covering wire {IBAN} or call {PHONE}. {FILLER}Updates optional."
    );
    let result = extract_docx(&body, "a.docx").await;

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak("a.docx", doc, &plants);
    assert_tokens_present("a.docx", &doc.content, &[EMAIL_LABEL, IBAN_LABEL]);
    cleanup().await;
}

/// docx #2: card + IP + provider-prefixed security token.
#[tokio::test]
async fn corpus_docx_b() {
    let _guard = seq().lock().await;
    cleanup().await;
    install_gate().await;

    let plants = [(CARD_LABEL, CARD), (IP_LABEL, IP), (TOKEN_LABEL, TOKEN)];
    let body = format!("Charge {CARD} from {IP} with token {TOKEN}. {FILLER}Ends neutral.");
    let result = extract_docx(&body, "b.docx").await;

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak("b.docx", doc, &plants);
    assert_tokens_present("b.docx", &doc.content, &[CARD_LABEL, TOKEN_LABEL]);
    cleanup().await;
}

/// xlsx #1: email + card in inline-string cells.
#[tokio::test]
async fn corpus_xlsx_a() {
    let _guard = seq().lock().await;
    cleanup().await;
    install_gate().await;

    let plants = [(EMAIL_LABEL, EMAIL), (CARD_LABEL, CARD)];
    let result = extract_xlsx(&[EMAIL, CARD, FILLER], "a.xlsx").await;

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak("a.xlsx", doc, &plants);
    assert_tokens_present("a.xlsx", &doc.content, &[EMAIL_LABEL, CARD_LABEL]);
    cleanup().await;
}

/// xlsx #2: IBAN + phone cells.
#[tokio::test]
async fn corpus_xlsx_b() {
    let _guard = seq().lock().await;
    cleanup().await;
    install_gate().await;

    let plants = [(IBAN_LABEL, IBAN), (PHONE_LABEL, PHONE)];
    let result = extract_xlsx(&[IBAN, PHONE, FILLER], "b.xlsx").await;

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak("b.xlsx", doc, &plants);
    assert_tokens_present("b.xlsx", &doc.content, &[IBAN_LABEL, PHONE_LABEL]);
    cleanup().await;
}

/// pptx #1: email + IBAN on the slide.
#[tokio::test]
async fn corpus_pptx_a() {
    let _guard = seq().lock().await;
    cleanup().await;
    install_gate().await;

    let plants = [(EMAIL_LABEL, EMAIL), (IBAN_LABEL, IBAN)];
    let result = extract_pptx(
        &format!("Wire details {IBAN} to {EMAIL}. {FILLER}Thanks."),
        "a.pptx",
    )
    .await;

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak("a.pptx", doc, &plants);
    assert_tokens_present("a.pptx", &doc.content, &[EMAIL_LABEL, IBAN_LABEL]);
    cleanup().await;
}

/// pptx #2: card + phone.
#[tokio::test]
async fn corpus_pptx_b() {
    let _guard = seq().lock().await;
    cleanup().await;
    install_gate().await;

    let plants = [(CARD_LABEL, CARD), (PHONE_LABEL, PHONE)];
    let result = extract_pptx(
        &format!("Call {PHONE} about {CARD}. {FILLER}Done."),
        "b.pptx",
    )
    .await;

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak("b.pptx", doc, &plants);
    assert_tokens_present("b.pptx", &doc.content, &[CARD_LABEL, PHONE_LABEL]);
    cleanup().await;
}

/// PDF: email + card + IBAN in one text object; chunking forced.
#[tokio::test]
async fn corpus_pdf() {
    let _guard = seq().lock().await;
    cleanup().await;
    install_gate().await;

    let plants = [(EMAIL_LABEL, EMAIL), (CARD_LABEL, CARD), (IBAN_LABEL, IBAN)];
    let body = format!("Statement: card {CARD}, wire {IBAN} contact {EMAIL}. {FILLER}nothing");
    let input = ExtractInput::from_bytes(
        pdf_fixture(&body),
        "application/pdf",
        Some("a.pdf".to_owned()),
    );
    let result = extract_installed(engine_with_secrets().await, input).await;

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak("a.pdf", doc, &plants);
    assert_tokens_present(
        "a.pdf",
        &doc.content,
        &[EMAIL_LABEL, CARD_LABEL, IBAN_LABEL],
    );
    cleanup().await;
}

/// Plain text: every no-network class planted at once; chunked.
#[tokio::test]
async fn corpus_txt_mixed() {
    let _guard = seq().lock().await;
    cleanup().await;
    install_gate().await;

    let plants = [
        (EMAIL_LABEL, EMAIL),
        (IBAN_LABEL, IBAN),
        (CARD_LABEL, CARD),
        (IP_LABEL, IP),
        (PHONE_LABEL, PHONE),
        (SSN_LABEL, SSN),
        (TOKEN_LABEL, TOKEN),
        (PASSWORD_LABEL, PASSWORD),
    ];
    let password_line = format!("password: {PASSWORD}\n");
    let body = format!(
        "Card {CARD}; wire {IBAN}; {PASSWORD_LABEL} guardian: token {TOKEN} from {IP}; SSN {SSN}; mail {EMAIL}; phone {PHONE}.\n{password_line}Notes follow. Nothing else."
    );
    let result = extract_txt(&body, "mixed.txt").await;

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak("mixed.txt", doc, &plants);
    assert_tokens_present(
        "mixed.txt",
        &doc.content,
        &[
            EMAIL_LABEL,
            IBAN_LABEL,
            CARD_LABEL,
            IP_LABEL,
            TOKEN_LABEL,
            PHONE_LABEL,
            SSN_LABEL,
        ],
    );
    cleanup().await;
}

/// Spec §2 one-way: `password` classes are configured for Drop — the value
/// is replaced with a visible `[REDACTED:PASSWORD]` marker (no rehydratable
/// token) and surfaces as a Drop-class finding, while tokenized classes
/// (email) still mint `[TYPE_N]`.
#[tokio::test]
async fn corpus_txt_one_way_password_drop() {
    let _guard = seq().lock().await;
    cleanup().await;

    // Install ONCE with the one-way labels; a second install would replace the
    // same-name plugin and silently reset the Drop configuration.
    GazeRedactor::install_with(engine_with_secrets().await, ["password"])
        .expect("install with one-way password labels");
    let input = text_input(
        &format!("Mail {EMAIL} for onboarding.\npassword: {PASSWORD}\nEnd."),
        "one-way.txt",
    );
    let result = xberg::core::extract::extract(input, &harness_config())
        .await
        .expect("extraction must succeed");

    let doc = result.results.first().expect("one document");
    assert_zero_raw_leak(
        "one-way.txt",
        doc,
        &[(PASSWORD_LABEL, PASSWORD), (EMAIL_LABEL, EMAIL)],
    );
    assert!(
        !doc.content.contains(&format!("[{PASSWORD_LABEL}_")),
        "ONE-WAY: fixture 'one-way.txt' minted a rehydratable password token: {:?}",
        doc.content
    );
    assert_tokens_present("one-way.txt", &doc.content, &[EMAIL_LABEL]);

    let report = doc.redaction_report.as_ref().expect("report attached");
    let drop_findings = report
        .findings
        .iter()
        .filter(|finding| finding.strategy == xberg::RedactionStrategy::Drop)
        .count();
    assert!(
        drop_findings >= 1,
        "ONE-WAY: expected Drop-class finding; report: {report:?}"
    );
    for finding in &report.findings {
        if finding.strategy == xberg::RedactionStrategy::Drop {
            assert!(
                finding.replacement_token == "[REDACTED:PASSWORD]",
                "ONE-WAY: Drop replacement must be visible marker: {finding:?}"
            );
        }
    }
    cleanup().await;
}
