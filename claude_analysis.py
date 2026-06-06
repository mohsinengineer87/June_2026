"""
claude_analysis.py
──────────────────
Claude AI integration for PASTA-ML Streamlit app.

Drop this file alongside your main app file, then follow the
3-line integration instructions at the bottom of this docstring.

INTEGRATION (add to your main app):
  1. Import at top:
       from claude_analysis import render_claude_tab

  2. Add tab to st.tabs() line (add ", tab_claude" to the unpacking
     and "🤖 Claude AI" to the list):
       (tab_overview, ..., tab_export, tab_claude) = st.tabs([
           ..., "📤 Export", "🤖 Claude AI"
       ])

  3. Add at the end of the file (after tab_export block):
       with tab_claude:
           render_claude_tab()

API KEY:
  Create .streamlit/secrets.toml with:
    ANTHROPIC_API_KEY = "sk-ant-..."
  OR set env var: ANTHROPIC_API_KEY=sk-ant-...
"""

import io, os, base64, textwrap
from datetime import datetime

import streamlit as st
import pandas as pd
import anthropic
from PIL import Image


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _get_client():
    """Return Anthropic client. Reads key from Streamlit secrets or env var."""
    key = None
    try:
        key = st.secrets["ANTHROPIC_API_KEY"]
    except Exception:
        key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        st.error(
            "❌ **ANTHROPIC_API_KEY not found.**  \n"
            "Add it to `.streamlit/secrets.toml`:  \n"
            "```toml\nANTHROPIC_API_KEY = 'sk-ant-...'\n```"
        )
        st.stop()
    return anthropic.Anthropic(api_key=key)


def _image_to_base64(img: Image.Image) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.standard_b64encode(buf.getvalue()).decode("utf-8")


def _collect_session_context() -> dict:
    """
    Pull live metrics out of st.session_state so Claude gets
    precise numbers, not just the screenshot.
    """
    ss = st.session_state
    ctx = {}

    # Step 2 — environment
    env = ss.get("env")
    if isinstance(env, dict):
        ctx["n_assets"]    = env.get("n_assets", "N/A")
        ctx["n_actors"]    = env.get("n_actors", "N/A")

    # Step 3 — scenarios
    sc = ss.get("scenarios")
    if sc is not None and hasattr(sc, "__len__"):
        ctx["n_scenarios"] = len(sc)

    # Step 5 — ML regression results
    ml = ss.get("ml_results")
    if isinstance(ml, dict) and ml:
        model_rows = []
        for name, r in ml.items():
            if isinstance(r, dict):
                model_rows.append({
                    "model":       name,
                    "r2":          r.get("r2",   "—"),
                    "mae":         r.get("mae",  "—"),
                    "rmse":        r.get("rmse", "—"),
                    "mape":        r.get("mape", "—"),
                    "cv_r2_mean":  r.get("cv_r2_mean", "—"),
                    "train_time_s":r.get("train_time_s", "—"),
                    "infer_ms":    r.get("infer_ms", "—"),
                })
        ctx["ml_models"] = model_rows
        ml_ml = [r for r in model_rows if "Baseline" not in r["model"] and "Dummy" not in r["model"]]
        if ml_ml:
            best = max(ml_ml, key=lambda r: float(r["r2"]) if r["r2"] != "—" else -1)
            ctx["best_model"]    = best["model"]
            ctx["best_r2"]       = best["r2"]
            ctx["best_mae"]      = best["mae"]

    # Step 5b — alerting / classifier
    clf = ss.get("clf_results")
    if isinstance(clf, dict) and clf and "error" not in clf:
        clf_rows = []
        for name, r in clf.items():
            if isinstance(r, dict):
                clf_rows.append({
                    "model":    name,
                    "f1":       r.get("f1",      "—"),
                    "roc_auc":  r.get("roc_auc", "—"),
                    "pr_auc":   r.get("pr_auc",  "—"),
                    "accuracy": r.get("accuracy","—"),
                })
        ctx["clf_models"] = clf_rows

    # Step 6 — scalability
    bench = ss.get("bench_complexity_fits")
    if isinstance(bench, dict) and bench:
        ctx["scalability_slopes"] = {
            stage: info.get("slope")
            for stage, info in bench.items()
            if isinstance(info, dict)
        }

    # Real-data bundle
    rdb = ss.get("real_data_bundle")
    if isinstance(rdb, dict):
        ctx["live_cve_rows"]      = rdb.get("n_cve_rows", "N/A")
        ctx["known_exploited"]    = rdb.get("n_known_exploited", "N/A")
        ctx["live_assets"]        = rdb.get("n_assets", "N/A")

    return ctx


def _format_context_for_prompt(ctx: dict) -> str:
    lines = ["### Live Experiment Context (from session_state)\n"]

    if "n_assets" in ctx:
        lines.append(f"- **Assets simulated:** {ctx['n_assets']}")
    if "n_actors" in ctx:
        lines.append(f"- **Threat actors:** {ctx['n_actors']}")
    if "n_scenarios" in ctx:
        lines.append(f"- **Scenarios generated:** {ctx['n_scenarios']:,}")

    if "ml_models" in ctx:
        lines.append("\n**Step 5 — ML Regression Models:**")
        for r in ctx["ml_models"]:
            lines.append(
                f"  - {r['model']}: R²={r['r2']} | MAE={r['mae']} | "
                f"RMSE={r['rmse']} | MAPE={r['mape']}% | CV_R²={r['cv_r2_mean']}"
            )

    if "clf_models" in ctx:
        lines.append("\n**Step 5b — Alerting Classifier Models:**")
        for r in ctx["clf_models"]:
            lines.append(
                f"  - {r['model']}: F1={r['f1']} | AUC={r['roc_auc']} | "
                f"PR-AUC={r['pr_auc']} | Acc={r['accuracy']}"
            )

    if "scalability_slopes" in ctx:
        lines.append("\n**Step 6 — Empirical Complexity Slopes (log-log fit):**")
        for stage, slope in ctx["scalability_slopes"].items():
            lines.append(f"  - {stage}: β̂₁ = {slope}")

    if "live_cve_rows" in ctx:
        lines.append(f"\n**Real Data Bundle:** {ctx['live_cve_rows']} CVE rows | "
                     f"{ctx['known_exploited']} known-exploited | "
                     f"{ctx['live_assets']} live assets")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# ANALYSIS PROMPTS — one per analysis mode
# ─────────────────────────────────────────────────────────────────────────────

PROMPTS = {

    "📊 Full Model Comparison": textwrap.dedent("""
        You are an expert ML researcher reviewing results from PASTA-ML, an ML-integrated
        threat-modeling framework for cyber-physical systems submitted to
        Expert Systems with Applications (ESWA).

        {context}

        Looking at the screenshot of experimental results, produce a structured analysis:

        ## 1. Model Performance Table
        Extract all visible model metrics (R², MAE, RMSE, MAPE, CV R², AUC) and
        present them in a clean ranked table, best to worst.

        ## 2. Champion Model
        Identify the best-performing model with exact numbers and explain *why* it
        outperforms the others (regularisation, ensemble diversity, etc.).

        ## 3. Baseline Gap
        Quantify the ΔR² improvement over the PASTA Formula Baseline.
        Is this gap large enough to justify ML (reviewers will ask)?

        ## 4. Reviewer Risk Flags
        List any results that look suspicious, inconsistent, or that a tough ESWA
        reviewer would flag (e.g. suspiciously high R², potential target leakage,
        missing confidence intervals).

        ## 5. Paper-Ready Narrative
        Write a 3–4 sentence Results paragraph suitable for Section 5.2 of the paper.
        Use precise numbers. Do not use first person.

        ## 6. Suggested Improvements Before Submission
        Up to 3 concrete additions that would strengthen the results section.
    """),

    "🔍 SHAP Feature Attribution": textwrap.dedent("""
        You are a cybersecurity ML explainability expert reviewing SHAP results from
        PASTA-ML (ESWA submission).

        {context}

        Analyse the SHAP feature importance plot in the screenshot:

        ## 1. Feature Ranking
        List all features in descending SHAP importance order with exact |φ| values
        if visible.

        ## 2. Live API Features
        Identify which top features come from live APIs:
        - cvss_weighted_avg → NVD CVE API (authoritative CVSS)
        - exploitability_score → FIRST EPSS (live exploit probability)
        - patch_compliance_inv → NVD / CISA KEV flag

        ## 3. Graph Topology Signal (RQ2 Answer)
        Find attack_path_length_inv in the ranking. Its position directly answers
        Research Question 2 of the paper:
        "Do graph-topology features provide significant risk signal?"
        Interpret the result — if it ranks top-5, RQ2 is answered affirmatively.

        ## 4. Practitioner Interpretation
        In plain English: what does this SHAP plot tell a SOC analyst about which
        factors drive the highest-risk assets in the simulation?

        ## 5. Suggested Figure Caption
        Write a publication-quality figure caption for this SHAP plot, suitable
        for the ESWA paper (≤3 sentences, include feature count and dataset size
        if visible).
    """),

    "🌐 Live Data Validation": textwrap.dedent("""
        You are a research validation expert reviewing live API ingestion results
        from PASTA-ML (ESWA submission).

        {context}

        Analyse the live data panel in the screenshot:

        ## 1. Sources Confirmed Active
        Which of these 8 sources are shown as active/loaded?
        CISA KEV | FIRST EPSS | NVD CVE API 2.0 | MITRE ATT&CK |
        OASIS STIX/TAXII | CycloneDX SBOM | SPDX SBOM | NIST CVSS

        ## 2. Record Counts
        Extract all visible row/record counts (e.g. KEV: 300 rows,
        EPSS: 300 rows, NVD: 200 CVEs). These numbers are critical for
        the paper's Section 4.6 validation claims.

        ## 3. Asset Inventory
        Summarise the asset table if visible (WEB-001, DB-001, their
        vuln counts, CVSS real, EPSS max, KEV count).

        ## 4. Section 4.6 Validation Statement
        Draft one sentence suitable for the paper:
        "Live validation confirms X CVE rows merged from Y/Z/W APIs
        into the PASTA-ML pipeline on [date], with R² = ..."

        ## 5. Anomalies or Gaps
        Flag anything unexpected — failed API calls, zero rows, missing
        fields, or anything that could weaken the live-validation claim
        during peer review.
    """),

    "📈 Scalability Analysis": textwrap.dedent("""
        You are a systems performance expert reviewing scalability benchmarks from
        PASTA-ML (ESWA submission).

        {context}

        Analyse the scalability chart/table in the screenshot:

        ## 1. Complexity Classes
        Extract the log-log slopes (β̂₁) for each pipeline phase visible:
        - Scenario generation
        - Feature engineering
        - ML training (XGBoost / RF)
        Are these consistent with O(N^1.4) claimed in the paper?

        ## 2. Runtime Table
        Reproduce all visible (N, time_s, memory_MB) rows.

        ## 3. Bottleneck Identification
        Which phase has the steepest slope? At what N does it become
        the dominant cost?

        ## 4. 5,000-Asset Claim
        Based on the trend, does the chart support deploying PASTA-ML
        at 5,000 assets on commodity hardware (16 GB RAM)?
        Extrapolate if needed.

        ## 5. Suggested Figure Caption
        Write a publication-quality caption for this scalability figure,
        suitable for Section 5.12 of the ESWA paper.
    """),

    "🧪 Permutation Test Review": textwrap.dedent("""
        You are a statistical ML reviewer examining the permutation test results
        from PASTA-ML (ESWA submission).

        {context}

        Analyse the permutation test output in the screenshot:

        ## 1. Test Summary
        What is the true R² vs. permuted R²? What is the p-value?
        Does the null distribution (all 100 runs < 0.09) fully exclude
        the true R²?

        ## 2. Target Leakage Assessment
        The permutation test is designed to rule out formula re-learning
        (where ML just memorises the PASTA risk formula).
        Does the ~0.92-point R² collapse confirm genuine signal?
        Explain why this satisfies RQ1.

        ## 3. Reviewer Strength Rating
        Rate this evidence 1–5 for convincing a sceptical ML reviewer
        that the model learns real signal. Justify your rating.

        ## 4. Paper Interpretation Paragraph
        Write 2–3 sentences for Section 5.3 of the paper describing
        this permutation test result. Must include exact numbers.
    """),

    "📸 Screenshot + Paper Advice": textwrap.dedent("""
        You are a senior academic advisor helping prepare figures for an ESWA
        (Expert Systems with Applications) journal submission of PASTA-ML.

        {context}

        Looking at this screenshot from the Streamlit app:

        ## 1. Figure Quality Assessment
        Rate the screenshot's publication readiness (1–5) on:
        - Resolution / sharpness
        - Font size (minimum 8pt after scaling to column width)
        - Colour contrast and accessibility
        - Data-ink ratio (unnecessary visual clutter)

        ## 2. ESWA Format Compliance
        ESWA requires:
        - Minimum 300 DPI (600 for line art)
        - TIFF/EPS preferred; PNG acceptable
        - Single column: ~3.5 inches wide; double column: ~7 inches
        Flag any compliance issues.

        ## 3. Recommended Improvements
        List up to 5 specific changes to improve this figure for publication
        (font size, axis labels, legend position, colour scheme, etc.).

        ## 4. Suggested Caption
        Write a publication-quality figure caption (≤3 sentences) for
        whatever result is shown in the screenshot.

        ## 5. Export Recommendation
        Should this figure be: (a) exported via Plotly write_image at
        scale=3, (b) re-made as a matplotlib figure for cleaner print
        output, or (c) used as-is? Justify.
    """),
}


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RENDER FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def render_claude_tab():
    """
    Call this inside `with tab_claude:` in your main app file.
    Renders the full Claude AI analysis panel.
    """
    st.subheader("🤖 Claude AI — Results Analysis & Paper Assistant")
    st.markdown(
        "<div style='background:#f0f6ff;border-left:4px solid #1a73e8;"
        "padding:10px 14px;border-radius:6px;margin-bottom:12px;'>"
        "Upload a screenshot of any PASTA-ML results panel. Claude will analyse it "
        "alongside your live session metrics and produce publication-ready insights, "
        "paper paragraphs, and figure captions for your ESWA submission."
        "</div>",
        unsafe_allow_html=True
    )

    # ── Row 1: Mode selector + context toggle ────────────────────────────────
    col_mode, col_ctx = st.columns([3, 1])
    with col_mode:
        mode = st.selectbox(
            "Analysis Mode",
            list(PROMPTS.keys()),
            help="Choose what Claude focuses on in its analysis."
        )
    with col_ctx:
        use_ctx = st.toggle(
            "Include live metrics",
            value=True,
            help="Pass your session_state metrics to Claude alongside the screenshot."
        )

    # ── Row 2: Upload ────────────────────────────────────────────────────────
    uploaded = st.file_uploader(
        "📸 Upload screenshot (PNG / JPG)",
        type=["png", "jpg", "jpeg"],
        help=(
            "Take a screenshot of any PASTA-ML tab using your browser's built-in tool:\n"
            "• **Chrome:** F12 → Ctrl+Shift+P → 'Capture full size screenshot'\n"
            "• **Firefox:** F12 → ⋮ → 'Take a Screenshot' → 'Save Full Page'"
        )
    )

    # Show preview
    image = None
    if uploaded:
        image = Image.open(uploaded)
        # Resize preview only — keep original for API
        preview = image.copy()
        preview.thumbnail((900, 600))
        st.image(preview, caption=f"Screenshot: {uploaded.name}", use_column_width=True)

    # ── Live context panel ───────────────────────────────────────────────────
    ctx = _collect_session_context()
    if use_ctx:
        with st.expander("📊 Live session metrics (sent to Claude)", expanded=False):
            if ctx:
                ctx_df_rows = []
                if "n_assets" in ctx:
                    ctx_df_rows.append({"Metric": "Assets simulated", "Value": ctx["n_assets"]})
                if "n_scenarios" in ctx:
                    ctx_df_rows.append({"Metric": "Scenarios", "Value": f"{ctx['n_scenarios']:,}"})
                if "best_model" in ctx:
                    ctx_df_rows.append({"Metric": "Best model", "Value": ctx["best_model"]})
                    ctx_df_rows.append({"Metric": "Best R²", "Value": ctx["best_r2"]})
                    ctx_df_rows.append({"Metric": "Best MAE", "Value": ctx["best_mae"]})
                if "live_cve_rows" in ctx:
                    ctx_df_rows.append({"Metric": "Live CVE rows", "Value": ctx["live_cve_rows"]})

                if ctx_df_rows:
                    st.dataframe(
                        pd.DataFrame(ctx_df_rows),
                        hide_index=True,
                        use_container_width=True
                    )

                # Full ML table
                if "ml_models" in ctx:
                    st.markdown("**ML Regression Models**")
                    st.dataframe(
                        pd.DataFrame(ctx["ml_models"]),
                        hide_index=True,
                        use_container_width=True
                    )
                if "clf_models" in ctx:
                    st.markdown("**Alerting Classifier Models**")
                    st.dataframe(
                        pd.DataFrame(ctx["clf_models"]),
                        hide_index=True,
                        use_container_width=True
                    )
            else:
                st.info(
                    "No session metrics yet — run Steps 2–6 first to populate "
                    "live context. Claude will still analyse the screenshot alone."
                )

    # ── Analyse button ───────────────────────────────────────────────────────
    st.divider()
    can_analyse = image is not None
    if not can_analyse:
        st.info("👆 Upload a screenshot to enable analysis.")

    if st.button(
        "🧠 Analyse with Claude",
        type="primary",
        disabled=not can_analyse,
        use_container_width=True
    ):
        context_str = _format_context_for_prompt(ctx) if (use_ctx and ctx) else ""
        prompt = PROMPTS[mode].format(context=context_str)

        with st.spinner("Claude is reading your results…"):
            try:
                client = _get_client()
                response = client.messages.create(
                    model="claude-opus-4-5",
                    max_tokens=2500,
                    messages=[
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "image",
                                    "source": {
                                        "type": "base64",
                                        "media_type": "image/png",
                                        "data": _image_to_base64(image),
                                    },
                                },
                                {"type": "text", "text": prompt},
                            ],
                        }
                    ],
                )
                analysis = response.content[0].text
                st.session_state["_claude_last_analysis"] = analysis
                st.session_state["_claude_last_mode"]     = mode
                st.session_state["_claude_last_ts"]       = datetime.now().strftime(
                    "%d %b %Y %H:%M"
                )

            except anthropic.APIError as e:
                st.error(f"Anthropic API error: {e}")
                return
            except Exception as e:
                st.error(f"Unexpected error: {e}")
                return

    # ── Display result ───────────────────────────────────────────────────────
    if st.session_state.get("_claude_last_analysis"):
        analysis = st.session_state["_claude_last_analysis"]
        ts       = st.session_state.get("_claude_last_ts", "")
        last_mode = st.session_state.get("_claude_last_mode", "")

        st.success(f"✅ Analysis complete — {last_mode} · {ts}")
        st.markdown("---")
        st.markdown(analysis)
        st.markdown("---")

        # Download buttons
        dcol1, dcol2 = st.columns(2)
        with dcol1:
            st.download_button(
                "📥 Download Analysis (.txt)",
                data=analysis.encode("utf-8"),
                file_name=f"claude_analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
                mime="text/plain",
                use_container_width=True,
            )
        with dcol2:
            # Markdown download (paste directly into paper draft)
            md_content = (
                f"# PASTA-ML Claude Analysis\n"
                f"**Mode:** {last_mode}  \n"
                f"**Generated:** {ts}\n\n"
                f"---\n\n"
                f"{analysis}"
            )
            st.download_button(
                "📄 Download as Markdown (.md)",
                data=md_content.encode("utf-8"),
                file_name=f"claude_analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.md",
                mime="text/markdown",
                use_container_width=True,
            )

    # ── Quick guide ──────────────────────────────────────────────────────────
    with st.expander("📖 How to get the best screenshots for each mode", expanded=False):
        st.markdown("""
| Analysis Mode | Best screenshot to take |
|---|---|
| 📊 Full Model Comparison | Step 5 tab → full regression metrics table |
| 🔍 SHAP Attribution | Step 5 tab → SHAP bar chart (scroll down) |
| 🌐 Live Data Validation | Real Data + CTI tab → live bundle summary |
| 📈 Scalability Analysis | Step 6 tab → log-log chart + runtime table |
| 🧪 Permutation Test | Step 5 tab → permutation test histogram |
| 📸 Screenshot + Paper Advice | Any tab — get figure quality feedback |

**Chrome screenshot tip:**  
`F12` → `Ctrl+Shift+P` → type `screenshot` → **Capture full size screenshot**

**Firefox screenshot tip:**  
`F12` → click `⋮` → **Take a Screenshot** → **Save Full Page**
        """)
