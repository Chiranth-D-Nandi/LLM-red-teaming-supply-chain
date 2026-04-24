import sys
import os
import json
import streamlit as st

#make sure root is on the path
_AEGIS_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AEGIS_ROOT not in sys.path:
    sys.path.insert(0, _AEGIS_ROOT)

from core.engine import run_full_assessment
from risk.sarif_export import generate_sarif
from risk.compliance import map_compliance

st.set_page_config(page_title='Growler Security', page_icon='🛡️',
                   layout='wide', initial_sidebar_state='expanded')

#inject dark theme css if exists
css_path = os.path.join(_AEGIS_ROOT, 'ui', 'themes', 'dark.css')
if os.path.exists(css_path):
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

SEVERITY_COLORS = {
    'CRITICAL': '#FF4B4B', 'HIGH': '#FF6B35',
    'MEDIUM': '#FFB800', 'LOW': '#1E90FF', 'INFO': '#808080'
}

VERDICT_COLORS = {
    'CRITICAL_DENY': '#ff4747', 'DENY': '#fca503',
    'CONDITIONAL': '#a4eb34', 'APPROVE': '#a4eb34'
}


def render_verdict_card(risk: dict):
    verdict = risk.get('verdict', 'UNKNOWN')
    score = risk.get('score', 0)
    color = VERDICT_COLORS.get(verdict, '#808080')
    
    st.markdown(f"""
    <div class='verdict-card'>
        <h5 style='color:var(--text-secondary); margin:0;'>VERDICT</h5>
        <h1 style='color:{color}; margin:10px 0 0 0; font-size:3em;'>{verdict}</h1>
        <h2 style='margin:10px 0; font-size:1.8em;'>Risk Score: {score} <span style='color:var(--text-secondary); font-size:0.6em;'>/ 10</span></h2>
        <p style='margin:0; color:var(--text-secondary);'>{risk.get('reason', '')}</p>
    </div>""", unsafe_allow_html=True)
    
    cols = st.columns(5)
    by_sev = risk.get('by_severity', {})
    for col, (sev, count) in zip(cols, by_sev.items()):
        col.metric(sev, count)


def render_attack_chains(chains: list):
    if not chains:
        st.info('No compound attack chains detected.')
        return
        
    st.subheader(f'⚡ {len(chains)} Attack Chain(s) Detected')
    for chain in chains:
        sev = chain.get('compound_severity', 'HIGH')
        color = SEVERITY_COLORS.get(sev, '#FF4B4B')
        comp_tags = ', '.join(chain.get('compliance', []))
        comp_html = f"<small>Compliance: {comp_tags}</small>" if comp_tags else ""
        
        st.markdown(f"""
        <div class='chain-card'>
            <h4 style='color:{color}; margin:0;'>{sev} — {chain.get('name', '')}</h4>
            <p style='margin:12px 0; color:var(--text-secondary);'>{chain.get('narrative', '')}</p>
            <div style='display:flex; gap:10px;'>
                {comp_html}
            </div>
        </div>""", unsafe_allow_html=True)


def render_findings_table(findings: list, scored: list):
    scored_map = {f['finding'].get('issue', ''): f['score'] for f in scored}
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    
    sorted_findings = sorted(findings, key=lambda f: (
        severity_order.get(f.get('severity'), 5),
        -scored_map.get(f.get('issue', ''), 0)
    ))
    
    for finding in sorted_findings:
        sev = finding.get('severity', 'INFO')
        color = SEVERITY_COLORS.get(sev, '#808080')
        score = scored_map.get(finding.get('issue', ''), 0)
        
        with st.expander(f"{sev} [{score:.1f}] {finding.get('rule_id','')} — {finding.get('issue', '')[:80]}"):
            cols = st.columns(3)
            compliance = map_compliance(finding)
            cols[0].markdown(f"**File:** `{finding.get('file','')}`")
            cols[1].markdown(f"**OWASP:** {compliance.get('owasp','')} {compliance.get('owasp_name','')}")
            cols[2].markdown(f"**CWE:** {compliance.get('cwe','')}")
            
            if finding.get('payload'):
                st.markdown('**Payload sent:**')
                st.code(finding['payload'], language='text')
            if finding.get('response'):
                st.markdown('**Model response:**')
                st.code(finding['response'], language='text')
            if finding.get('actual_value'):
                st.markdown(f"**Actual value:** `{finding['actual_value']}`")


def render_robustness_tier(tier: int):
    tier_labels = {
        0: 'No resistance — direct injection succeeded',
        1: 'Minimal — blocks naive but fails delimiter injection',
        2: 'Low — blocks delimiter but fails encoding bypass',
        3: 'Moderate — blocks encoding but fails semantic attacks',
        4: 'Strong — blocks semantic but fails multi-turn escalation',
        5: 'Robust — resisted all tested techniques',
    }
    colors = ['#FF0000', '#FF4B4B', '#FF8C00', '#FFB800', '#90EE90', '#00C851']
    color = colors[min(tier, 5)]
    label = tier_labels.get(tier, 'Unknown')
    
    st.markdown(f"""
    <div class='verdict-card'>
        <h5 style="color:var(--text-secondary); margin:0;">INJECTION RESISTANCE DEPTH</h5>
        <h3 style="color:var(--text-primary); margin:10px 0 20px 0;">Tier {tier}/5</h3>
        <div class='tier-bar-bg'>
            <div class='tier-bar-fill' style='width:{tier*20}%; background:{color};'></div>
        </div>
        <p style='color:var(--text-secondary); margin:16px 0 0 0; font-weight:600;'>{label}</p>
    </div>""", unsafe_allow_html=True)


def render_risk_breakdown(risk: dict, phase_scores: dict):
    try:
        import plotly.graph_objects as go
        categories = list(phase_scores.keys())
        scores = list(phase_scores.values())
        bar_colors = [SEVERITY_COLORS.get(
            'CRITICAL' if s >= 9 else 'HIGH' if s >= 7 else
            'MEDIUM' if s >= 4 else 'LOW', '#808080') for s in scores]
            
        fig = go.Figure(go.Bar(x=categories, y=scores, marker_color=bar_colors,
                               text=[f'{s:.1f}' for s in scores], textposition='auto'))
        fig.update_layout(yaxis_range=[0, 10], plot_bgcolor='rgba(0,0,0,0)',
                          paper_bgcolor='rgba(0,0,0,0)', font_color='white',
                          title='Risk by Category')
        st.plotly_chart(fig, use_container_width=True)
    except ImportError:
        st.warning("Plotly is not installed. Run `pip install plotly` to see the chart.")


#main app flow
st.title('🛡️ Growler Security — AI Model Security Assessment')

with st.sidebar:
    model_id = st.text_input('HuggingFace Model ID', 'microsoft/phi-2')
    backend = st.selectbox('Inference Backend', ['ollama', 'groq'])
    api_key = None
    if backend == 'groq':
        api_key = st.text_input('Groq API Key', type='password')
    scan_btn = st.button('🔍 SCAN', type='primary', use_container_width=True)
    load_demo_btn = st.button('📁 Load Demo Result', use_container_width=True)

if scan_btn or load_demo_btn:
    with st.spinner('Running Growler Security assessment...'):
        if load_demo_btn:
            try:
                demo_path = os.path.join(os.path.dirname(__file__), 'growler_results.json')
                with open(demo_path, 'r') as f:
                    result = json.load(f)
            except Exception as e:
                st.error(f"Could not load demo results: {e}")
                st.stop()
        else:
            result = run_full_assessment(model_id, backend, api_key=api_key)
        
        tab1, tab2, tab3, tab4 = st.tabs([
            '📊 Verdict & Risk', '🔴 Attack Findings',
            '⚡ Attack Chains', '📄 Export'
        ])
        
        with tab1:
            render_verdict_card(result['risk'])
            render_robustness_tier(result.get('robustness_tier', 0))
            render_risk_breakdown(result['risk'], result['phase_scores'])
            
        with tab2:
            render_findings_table(result['all_findings'], result['scored_findings'])
            
        with tab3:
            render_attack_chains(result['attack_chains'])
            
        with tab4:
            sarif = generate_sarif(result)
            st.download_button('Download SARIF', json.dumps(sarif, indent=2),
                               'growler_results.sarif', 'application/json')
            st.download_button('Download JSON', json.dumps(result, indent=2, default=str),
                               'growler_results.json', 'application/json')
            st.code(json.dumps(sarif, indent=2)[:2000] + '...', language='json')
