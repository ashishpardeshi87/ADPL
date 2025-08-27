"""
Investigator Dashboard
Web-based dashboard for threat monitoring and investigation
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import asyncio
import websocket
import threading
from typing import Dict, List, Optional
import redis
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import ThreatDetector, MetadataExtractor, DeviceFingerprinter, BehavioralProfiler

# Page configuration
st.set_page_config(
    page_title="Hoax Threat Detection System",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .threat-critical {
        background-color: #ff4444;
        color: white;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    .threat-high {
        background-color: #ff8800;
        color: white;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    .threat-medium {
        background-color: #ffbb00;
        color: black;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    .threat-low {
        background-color: #88dd00;
        color: black;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

class DashboardApp:
    """Main dashboard application"""
    
    def __init__(self):
        """Initialize dashboard"""
        # Initialize session state
        if 'alerts' not in st.session_state:
            st.session_state.alerts = []
        if 'selected_alert' not in st.session_state:
            st.session_state.selected_alert = None
        if 'profiles' not in st.session_state:
            st.session_state.profiles = []
        if 'statistics' not in st.session_state:
            st.session_state.statistics = {
                'total_threats': 0,
                'critical_threats': 0,
                'resolved_threats': 0,
                'active_investigations': 0
            }
        
        # Initialize components
        self.threat_detector = ThreatDetector()
        self.metadata_extractor = MetadataExtractor()
        self.device_fingerprinter = DeviceFingerprinter()
        self.behavioral_profiler = BehavioralProfiler()
        
        # Initialize Redis connection
        self.redis_client = self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        try:
            client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True
            )
            client.ping()
            return client
        except:
            return None
    
    def run(self):
        """Run the dashboard application"""
        # Header
        st.title("🔍 Hoax Threat Detection System")
        st.markdown("### Real-time Threat Monitoring and Investigation Dashboard")
        
        # Sidebar
        with st.sidebar:
            st.header("Navigation")
            page = st.selectbox(
                "Select Page",
                ["Overview", "Real-time Monitor", "Threat Analysis", 
                 "Device Tracking", "Behavioral Profiles", "Investigation Tools",
                 "Reports", "Settings"]
            )
        
        # Main content
        if page == "Overview":
            self.show_overview()
        elif page == "Real-time Monitor":
            self.show_realtime_monitor()
        elif page == "Threat Analysis":
            self.show_threat_analysis()
        elif page == "Device Tracking":
            self.show_device_tracking()
        elif page == "Behavioral Profiles":
            self.show_behavioral_profiles()
        elif page == "Investigation Tools":
            self.show_investigation_tools()
        elif page == "Reports":
            self.show_reports()
        elif page == "Settings":
            self.show_settings()
    
    def show_overview(self):
        """Show overview page"""
        st.header("System Overview")
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Threats Detected",
                st.session_state.statistics['total_threats'],
                delta="+12 today"
            )
        
        with col2:
            st.metric(
                "Critical Threats",
                st.session_state.statistics['critical_threats'],
                delta="+2 today",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                "Resolved Threats",
                st.session_state.statistics['resolved_threats'],
                delta="+5 today"
            )
        
        with col4:
            st.metric(
                "Active Investigations",
                st.session_state.statistics['active_investigations'],
                delta="-1 today"
            )
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Threat Trends (Last 7 Days)")
            self.plot_threat_trends()
        
        with col2:
            st.subheader("Threat Sources")
            self.plot_threat_sources()
        
        # Recent alerts
        st.subheader("Recent Alerts")
        self.show_recent_alerts()
        
        # Active investigations
        st.subheader("Active Investigations")
        self.show_active_investigations()
    
    def show_realtime_monitor(self):
        """Show real-time monitoring page"""
        st.header("Real-time Threat Monitor")
        
        # Connection status
        col1, col2, col3 = st.columns(3)
        with col1:
            st.success("✅ Email Monitor: Active")
        with col2:
            st.success("✅ Twitter Monitor: Active")
        with col3:
            st.warning("⚠️ Telegram Monitor: Connecting...")
        
        # Live feed
        st.subheader("Live Threat Feed")
        
        # Create placeholder for live updates
        feed_placeholder = st.empty()
        
        # Simulate live feed (in production, would connect to WebSocket)
        if st.button("Start Live Monitoring"):
            self.start_live_monitoring(feed_placeholder)
        
        # Manual threat submission
        st.subheader("Manual Threat Analysis")
        with st.form("manual_threat"):
            text = st.text_area("Enter suspicious text for analysis")
            source = st.selectbox("Source", ["Email", "Social Media", "Web", "Other"])
            
            if st.form_submit_button("Analyze"):
                self.analyze_manual_threat(text, source)
    
    def show_threat_analysis(self):
        """Show threat analysis page"""
        st.header("Threat Analysis")
        
        # Search and filters
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            threat_level = st.selectbox(
                "Threat Level",
                ["All", "Critical", "High", "Medium", "Low"]
            )
        with col2:
            date_range = st.date_input(
                "Date Range",
                value=(datetime.now() - timedelta(days=7), datetime.now())
            )
        with col3:
            source_filter = st.selectbox(
                "Source",
                ["All", "Email", "Twitter", "Telegram", "Facebook"]
            )
        with col4:
            status = st.selectbox(
                "Status",
                ["All", "New", "Under Investigation", "Resolved", "False Positive"]
            )
        
        # Threat list
        threats = self.get_filtered_threats(threat_level, date_range, source_filter, status)
        
        if threats:
            # Display threats in a table
            df = pd.DataFrame(threats)
            selected_threat = st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                selection_mode="single-row"
            )
            
            # Detailed view of selected threat
            if st.button("View Details"):
                self.show_threat_details(selected_threat)
        else:
            st.info("No threats found matching the filters")
    
    def show_device_tracking(self):
        """Show device tracking page"""
        st.header("Device Tracking")
        
        # Device search
        device_id = st.text_input("Enter Device Fingerprint ID")
        
        if device_id:
            device_info = self.get_device_info(device_id)
            if device_info:
                # Display device information
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Device Information")
                    st.json(device_info['attributes'])
                
                with col2:
                    st.subheader("Risk Assessment")
                    st.metric("Risk Score", f"{device_info['risk_score']:.2f}")
                    st.metric("Confidence", f"{device_info['confidence']:.2f}")
                
                # Threat history
                st.subheader("Threat History")
                if device_info.get('threat_history'):
                    df = pd.DataFrame(device_info['threat_history'])
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No threat history for this device")
                
                # Linked devices
                st.subheader("Potentially Linked Devices")
                linked = self.get_linked_devices(device_id)
                if linked:
                    st.write(linked)
                else:
                    st.info("No linked devices found")
        
        # Device statistics
        st.subheader("Device Statistics")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Devices Tracked", "1,234")
        with col2:
            st.metric("High-Risk Devices", "45")
        with col3:
            st.metric("New Devices (Today)", "23")
    
    def show_behavioral_profiles(self):
        """Show behavioral profiles page"""
        st.header("Behavioral Profiles")
        
        # Profile search
        profile_id = st.text_input("Enter Profile ID or Search Term")
        
        # Profile list
        profiles = self.get_behavioral_profiles(profile_id)
        
        if profiles:
            # Display profiles
            for profile in profiles:
                with st.expander(f"Profile: {profile['profile_id']}"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write("**Writing Style:**")
                        st.json(profile.get('writing_style', {}))
                    
                    with col2:
                        st.write("**Temporal Patterns:**")
                        st.json(profile.get('temporal_patterns', {}))
                    
                    with col3:
                        st.write("**Risk Indicators:**")
                        for indicator in profile.get('risk_indicators', []):
                            st.warning(indicator)
                    
                    # Link profiles
                    if st.button(f"Find Similar Profiles", key=profile['profile_id']):
                        similar = self.find_similar_profiles(profile)
                        st.write("Similar profiles:", similar)
        else:
            st.info("No behavioral profiles found")
        
        # Profile statistics
        st.subheader("Profile Statistics")
        self.plot_profile_statistics()
    
    def show_investigation_tools(self):
        """Show investigation tools page"""
        st.header("Investigation Tools")
        
        # Tool selection
        tool = st.selectbox(
            "Select Tool",
            ["Text Analysis", "Metadata Extraction", "IP Lookup", 
             "Email Header Analysis", "Link Analysis"]
        )
        
        if tool == "Text Analysis":
            self.show_text_analysis_tool()
        elif tool == "Metadata Extraction":
            self.show_metadata_extraction_tool()
        elif tool == "IP Lookup":
            self.show_ip_lookup_tool()
        elif tool == "Email Header Analysis":
            self.show_email_header_analysis_tool()
        elif tool == "Link Analysis":
            self.show_link_analysis_tool()
    
    def show_text_analysis_tool(self):
        """Show text analysis tool"""
        st.subheader("Text Analysis Tool")
        
        text = st.text_area("Enter text to analyze", height=200)
        
        if st.button("Analyze Text"):
            if text:
                # Perform analysis
                analysis = self.threat_detector.detect_threat(text)
                
                # Display results
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Threat Assessment:**")
                    threat_class = f"threat-{analysis.threat_level.name.lower()}"
                    st.markdown(
                        f'<div class="{threat_class}">Threat Level: {analysis.threat_level.name}</div>',
                        unsafe_allow_html=True
                    )
                    st.metric("Confidence", f"{analysis.confidence:.2%}")
                    st.metric("Urgency Score", f"{analysis.urgency_score:.2f}")
                    st.metric("Credibility Score", f"{analysis.credibility_score:.2f}")
                
                with col2:
                    st.write("**Detected Elements:**")
                    if analysis.detected_keywords:
                        st.write("Keywords:", analysis.detected_keywords)
                    if analysis.matched_patterns:
                        st.write("Patterns:", analysis.matched_patterns)
                    st.write("Explanation:", analysis.explanation)
    
    def show_metadata_extraction_tool(self):
        """Show metadata extraction tool"""
        st.subheader("Metadata Extraction Tool")
        
        source_type = st.selectbox("Source Type", ["Email", "Web Request", "Social Media"])
        
        if source_type == "Email":
            email_headers = st.text_area("Paste email headers", height=200)
            if st.button("Extract Metadata"):
                if email_headers:
                    # Extract metadata
                    metadata = self.metadata_extractor.extract_from_email(
                        email_headers.encode(),
                        {}
                    )
                    st.json(metadata)
    
    def show_reports(self):
        """Show reports page"""
        st.header("Reports")
        
        # Report type selection
        report_type = st.selectbox(
            "Select Report Type",
            ["Daily Summary", "Weekly Analysis", "Threat Trends", 
             "Investigation Report", "Compliance Report"]
        )
        
        # Date range
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date", datetime.now() - timedelta(days=30))
        with col2:
            end_date = st.date_input("End Date", datetime.now())
        
        # Generate report button
        if st.button("Generate Report"):
            report = self.generate_report(report_type, start_date, end_date)
            
            # Display report
            st.markdown(report, unsafe_allow_html=True)
            
            # Download button
            st.download_button(
                "Download Report",
                data=report,
                file_name=f"{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.html",
                mime="text/html"
            )
    
    def show_settings(self):
        """Show settings page"""
        st.header("System Settings")
        
        # Tabs for different settings
        tab1, tab2, tab3, tab4 = st.tabs(
            ["Detection Settings", "Monitoring Settings", "Notifications", "System"]
        )
        
        with tab1:
            st.subheader("Detection Settings")
            
            confidence_threshold = st.slider(
                "Confidence Threshold",
                min_value=0.0,
                max_value=1.0,
                value=0.75,
                step=0.05
            )
            
            risk_levels = {
                "Low": st.slider("Low Risk Threshold", 0.0, 1.0, 0.3),
                "Medium": st.slider("Medium Risk Threshold", 0.0, 1.0, 0.6),
                "High": st.slider("High Risk Threshold", 0.0, 1.0, 0.85),
                "Critical": st.slider("Critical Risk Threshold", 0.0, 1.0, 0.95)
            }
            
            if st.button("Save Detection Settings"):
                st.success("Settings saved successfully!")
        
        with tab2:
            st.subheader("Monitoring Settings")
            
            email_enabled = st.checkbox("Enable Email Monitoring", value=True)
            twitter_enabled = st.checkbox("Enable Twitter Monitoring", value=True)
            telegram_enabled = st.checkbox("Enable Telegram Monitoring", value=True)
            facebook_enabled = st.checkbox("Enable Facebook Monitoring", value=False)
            
            check_interval = st.number_input(
                "Check Interval (seconds)",
                min_value=10,
                max_value=3600,
                value=30
            )
            
            if st.button("Save Monitoring Settings"):
                st.success("Settings saved successfully!")
        
        with tab3:
            st.subheader("Notification Settings")
            
            email_notifications = st.checkbox("Enable Email Notifications", value=True)
            sms_notifications = st.checkbox("Enable SMS Notifications", value=False)
            
            notification_email = st.text_input("Notification Email")
            notification_phone = st.text_input("Notification Phone")
            
            alert_levels = st.multiselect(
                "Send notifications for threat levels",
                ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"]
            )
            
            if st.button("Save Notification Settings"):
                st.success("Settings saved successfully!")
        
        with tab4:
            st.subheader("System Settings")
            
            data_retention = st.number_input(
                "Data Retention (days)",
                min_value=7,
                max_value=365,
                value=90
            )
            
            enable_audit = st.checkbox("Enable Audit Logging", value=True)
            enable_encryption = st.checkbox("Enable Data Encryption", value=True)
            
            st.write("**System Information:**")
            st.write("- Version: 1.0.0")
            st.write("- Database: PostgreSQL")
            st.write("- Cache: Redis")
            st.write("- Last Updated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            if st.button("Clear Cache"):
                st.success("Cache cleared successfully!")
    
    # Helper methods
    
    def plot_threat_trends(self):
        """Plot threat trends chart"""
        # Generate sample data
        dates = pd.date_range(end=datetime.now(), periods=7, freq='D')
        data = {
            'Date': dates,
            'Critical': [2, 1, 3, 2, 4, 1, 2],
            'High': [5, 7, 4, 6, 8, 5, 6],
            'Medium': [10, 12, 8, 11, 9, 13, 10],
            'Low': [15, 18, 20, 16, 14, 19, 17]
        }
        df = pd.DataFrame(data)
        
        # Create stacked area chart
        fig = go.Figure()
        
        for level in ['Low', 'Medium', 'High', 'Critical']:
            fig.add_trace(go.Scatter(
                x=df['Date'],
                y=df[level],
                mode='lines',
                stackgroup='one',
                name=level
            ))
        
        fig.update_layout(
            hovermode='x unified',
            height=300,
            margin=dict(l=0, r=0, t=0, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def plot_threat_sources(self):
        """Plot threat sources pie chart"""
        data = {
            'Source': ['Email', 'Twitter', 'Telegram', 'Facebook', 'Web'],
            'Count': [45, 30, 20, 15, 10]
        }
        df = pd.DataFrame(data)
        
        fig = px.pie(df, values='Count', names='Source', hole=0.4)
        fig.update_layout(
            height=300,
            margin=dict(l=0, r=0, t=0, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def show_recent_alerts(self):
        """Show recent alerts"""
        # Sample alerts
        alerts = [
            {
                'Time': '2 minutes ago',
                'Level': 'CRITICAL',
                'Source': 'Email',
                'Message': 'Bomb threat detected in email from suspicious sender'
            },
            {
                'Time': '15 minutes ago',
                'Level': 'HIGH',
                'Source': 'Twitter',
                'Message': 'Threatening message detected mentioning specific location'
            },
            {
                'Time': '1 hour ago',
                'Level': 'MEDIUM',
                'Source': 'Telegram',
                'Message': 'Suspicious activity in monitored channel'
            }
        ]
        
        for alert in alerts:
            threat_class = f"threat-{alert['Level'].lower()}"
            st.markdown(
                f'''<div class="{threat_class}">
                    <strong>{alert["Time"]}</strong> - {alert["Source"]}<br>
                    {alert["Message"]}
                </div>''',
                unsafe_allow_html=True
            )
    
    def show_active_investigations(self):
        """Show active investigations"""
        investigations = [
            {
                'ID': 'INV-2024-001',
                'Started': '2024-01-15',
                'Threat Level': 'HIGH',
                'Status': 'Analyzing behavioral patterns',
                'Progress': 65
            },
            {
                'ID': 'INV-2024-002',
                'Started': '2024-01-16',
                'Threat Level': 'CRITICAL',
                'Status': 'Awaiting law enforcement response',
                'Progress': 85
            }
        ]
        
        df = pd.DataFrame(investigations)
        st.dataframe(df, use_container_width=True, hide_index=True)
    
    def analyze_manual_threat(self, text: str, source: str):
        """Analyze manually submitted threat"""
        if text:
            analysis = self.threat_detector.detect_threat(text)
            
            st.success("Analysis complete!")
            st.write(f"Threat Level: {analysis.threat_level.name}")
            st.write(f"Confidence: {analysis.confidence:.2%}")
            st.write(f"Explanation: {analysis.explanation}")
    
    def get_filtered_threats(self, threat_level, date_range, source, status):
        """Get filtered threats from database"""
        # In production, would query actual database
        # Return sample data for demo
        return [
            {
                'ID': 'THR-001',
                'Date': '2024-01-16 14:30',
                'Level': 'HIGH',
                'Source': 'Email',
                'Status': 'Under Investigation',
                'Confidence': 0.85
            },
            {
                'ID': 'THR-002',
                'Date': '2024-01-16 15:45',
                'Level': 'CRITICAL',
                'Source': 'Twitter',
                'Status': 'New',
                'Confidence': 0.92
            }
        ]
    
    def get_device_info(self, device_id: str):
        """Get device information"""
        # In production, would query actual database
        return {
            'device_id': device_id,
            'attributes': {
                'user_agent': 'Mozilla/5.0...',
                'platform': 'Windows',
                'screen_resolution': '1920x1080'
            },
            'risk_score': 0.75,
            'confidence': 0.85,
            'threat_history': []
        }
    
    def get_linked_devices(self, device_id: str):
        """Get linked devices"""
        # In production, would use actual linking algorithm
        return []
    
    def get_behavioral_profiles(self, search_term: str):
        """Get behavioral profiles"""
        # In production, would query actual database
        return []
    
    def find_similar_profiles(self, profile: Dict):
        """Find similar behavioral profiles"""
        # In production, would use actual similarity algorithm
        return []
    
    def plot_profile_statistics(self):
        """Plot profile statistics"""
        # Sample data
        data = {
            'Profile Type': ['Aggressive', 'Technical', 'Emotional', 'Casual'],
            'Count': [15, 8, 12, 5]
        }
        df = pd.DataFrame(data)
        
        fig = px.bar(df, x='Profile Type', y='Count')
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    def show_ip_lookup_tool(self):
        """Show IP lookup tool"""
        st.subheader("IP Lookup Tool")
        
        ip_address = st.text_input("Enter IP Address")
        
        if st.button("Lookup"):
            if ip_address:
                st.info(f"Looking up {ip_address}...")
                # In production, would perform actual IP lookup
                st.write("Location: United States")
                st.write("ISP: Example ISP")
                st.write("Type: Residential")
    
    def show_email_header_analysis_tool(self):
        """Show email header analysis tool"""
        st.subheader("Email Header Analysis Tool")
        
        headers = st.text_area("Paste email headers", height=300)
        
        if st.button("Analyze Headers"):
            if headers:
                st.info("Analyzing headers...")
                # In production, would perform actual analysis
                st.write("SPF: Pass")
                st.write("DKIM: Pass")
                st.write("Sender IP: 192.168.1.1")
    
    def show_link_analysis_tool(self):
        """Show link analysis tool"""
        st.subheader("Link Analysis Tool")
        
        st.info("Visualize connections between threats, devices, and profiles")
        
        # In production, would show interactive network graph
        st.write("Link analysis visualization would appear here")
    
    def generate_report(self, report_type: str, start_date, end_date):
        """Generate report"""
        # In production, would generate actual report
        return f"""
        <h1>{report_type}</h1>
        <p>Report Period: {start_date} to {end_date}</p>
        <h2>Summary</h2>
        <p>This is a sample report. In production, this would contain actual data.</p>
        """
    
    def start_live_monitoring(self, placeholder):
        """Start live monitoring feed"""
        # In production, would connect to WebSocket
        import time
        import random
        
        for i in range(10):
            threat_level = random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
            source = random.choice(['Email', 'Twitter', 'Telegram'])
            
            placeholder.info(f"[{datetime.now().strftime('%H:%M:%S')}] {threat_level} threat detected from {source}")
            time.sleep(2)


def main():
    """Main function"""
    app = DashboardApp()
    app.run()


if __name__ == "__main__":
    main()