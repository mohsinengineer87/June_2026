# ─────────────────────────────────────────────────────────────────────────────
# HOW TO INTEGRATE claude_analysis.py INTO YOUR MAIN APP
# Apply these 3 small edits to 3June2026pasta_ml_app_enhanced.py
# ─────────────────────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════
# EDIT 1 — Add import near the top (after your existing imports, ~line 65)
# ══════════════════════════════════════════════════════════════════

# ADD THIS LINE:
from claude_analysis import render_claude_tab


# ══════════════════════════════════════════════════════════════════
# EDIT 2 — Add tab to st.tabs() block (~line 3860)
# ══════════════════════════════════════════════════════════════════

# FIND THIS (your current code):
(tab_overview,
 tab_step1, tab_step2, tab_step3,
 tab_step4, tab_step5, tab_step5b, tab_step6,
 tab_realdata, tab_ops, tab_export) = st.tabs([
    "🏠 Overview",
    "📐 Step 1 · Framework",
    "🏗️ Step 2 · Environment",
    "🎲 Step 3 · Scenarios",
    "🔧 Step 4 · Features",
    "🤖 Step 5 · ML Models",
    "🚨 Step 5b · Alerting",
    "⚡ Step 6 · Scalability",
    "🧩 Real Data + CTI",
    "🏛️ Ops + Governance",
    "📤 Export",
])

# REPLACE WITH (adds tab_claude + "🤖 Claude AI" tab):
(tab_overview,
 tab_step1, tab_step2, tab_step3,
 tab_step4, tab_step5, tab_step5b, tab_step6,
 tab_realdata, tab_ops, tab_export, tab_claude) = st.tabs([
    "🏠 Overview",
    "📐 Step 1 · Framework",
    "🏗️ Step 2 · Environment",
    "🎲 Step 3 · Scenarios",
    "🔧 Step 4 · Features",
    "🤖 Step 5 · ML Models",
    "🚨 Step 5b · Alerting",
    "⚡ Step 6 · Scalability",
    "🧩 Real Data + CTI",
    "🏛️ Ops + Governance",
    "📤 Export",
    "✨ Claude AI",
])


# ══════════════════════════════════════════════════════════════════
# EDIT 3 — Add tab body at the very end of the file (~line 6939)
# ══════════════════════════════════════════════════════════════════

# ADD THESE LINES AT THE END OF THE FILE:
with tab_claude:
    render_claude_tab()


# ══════════════════════════════════════════════════════════════════
# API KEY SETUP
# ══════════════════════════════════════════════════════════════════
# Create the file:  .streamlit/secrets.toml
# With contents:
#   ANTHROPIC_API_KEY = "sk-ant-your-key-here"
#
# OR set environment variable before running:
#   set ANTHROPIC_API_KEY=sk-ant-your-key-here    (Windows)
#   export ANTHROPIC_API_KEY=sk-ant-your-key-here  (Mac/Linux)
#
# Then run as normal:
#   streamlit run 3June2026pasta_ml_app_enhanced.py
