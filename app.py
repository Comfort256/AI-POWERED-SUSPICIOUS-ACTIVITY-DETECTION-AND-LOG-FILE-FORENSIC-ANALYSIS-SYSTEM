import streamlit as st
import plotly.express as px

from forensic.parser import parse_logs
from forensic.detector import detect_bruteforce
from forensic.analyzer import train_model
from forensic.evidence import save_evidence
from forensic.database import init_db, insert_incident

st.set_page_config(page_title='AI Forensic Dashboard', page_icon='🛡️', layout='wide')

st.markdown('''
<style>
.stApp {
    background: linear-gradient(to right, #0f172a, #1e293b);
    color: white;
}
h1,h2,h3 {
    color: #38bdf8;
}
</style>
''', unsafe_allow_html=True)

st.title('🛡️ AI-Powered Suspicious Activity Detection')

init_db()

logs_df = parse_logs('logs/sample_logs.txt')

col1, col2, col3 = st.columns(3)

with col1:
    st.metric('Total Logs', len(logs_df))

with col2:
    failed_count = len(logs_df[logs_df['event_type'] == 'LOGIN_FAILED'])
    st.metric('Failed Logins', failed_count)

with col3:
    malware_count = len(logs_df[logs_df['event_type'] == 'MALWARE_ALERT'])
    st.metric('Malware Alerts', malware_count)

st.subheader('📄 Raw Logs')
st.dataframe(logs_df, use_container_width=True)

chart_data = logs_df['event_type'].value_counts().reset_index()
chart_data.columns = ['Event Type', 'Count']

fig = px.bar(chart_data, x='Event Type', y='Count', template='plotly_dark')
st.plotly_chart(fig, use_container_width=True)

st.subheader('🚨 Suspicious Activity Detection')

suspicious = detect_bruteforce(logs_df)

if suspicious:
    for item in suspicious:
        st.error(f'Brute Force Detected: {item}')
        save_evidence(item)
        insert_incident('NOW', str(item))
else:
    st.success('No brute force detected')

st.subheader('🤖 AI Anomaly Detection')

analyzed_df = train_model(logs_df)

st.dataframe(analyzed_df, use_container_width=True)

anomalies = analyzed_df[analyzed_df['anomaly'] == -1]

st.subheader('⚠️ Detected Anomalies')
st.dataframe(anomalies, use_container_width=True)

report_content = f'''
AI-Powered Suspicious Activity Detection Report

Total Logs: {len(logs_df)}
Failed Login Attempts: {failed_count}
Malware Alerts: {malware_count}
Detected Anomalies: {len(anomalies)}

Suspicious Activities:
{suspicious}
'''

with st.expander('🔍 View Full Incident Report'):
    st.text(report_content)

st.download_button(
    label='⬇️ Download Incident Report',
    data=report_content,
    file_name='incident_report.txt',
    mime='text/plain'
)
