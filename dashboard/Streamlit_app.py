import os
import requests
import streamlit as st


API_BASE = os.getenv("API_BASE", "http://localhost:8000")
API_KEY = os.getenv("API_KEY", "change-me")


st.set_page_config(page_title="Threat Investigations", layout="wide")
st.title("Threat Investigations Dashboard")


def get_cases():
	resp = requests.get(f"{API_BASE}/api/cases/", headers={"x-api-key": API_KEY}, timeout=10)
	resp.raise_for_status()
	return resp.json()


def get_case_messages(case_id: int):
	resp = requests.get(f"{API_BASE}/api/cases/{case_id}/messages", headers={"x-api-key": API_KEY}, timeout=10)
	resp.raise_for_status()
	return resp.json()


cols = st.columns([2, 5])
with cols[0]:
	st.subheader("Cases")
	cases = get_cases()
	case_options = {f"Case {c['id']} · risk {c['risk_level']:.1f}": c for c in cases}
	selected_label = st.selectbox("Select Case", list(case_options.keys())) if cases else None
	selected_case = case_options[selected_label] if selected_label else None

with cols[1]:
	st.subheader("Details")
	if selected_case:
		st.write(selected_case)
		messages = get_case_messages(selected_case["id"]) or []
		for m in messages:
			with st.expander(f"Msg {m['id']} · {m['classification']} · score {m['risk_score']:.1f}"):
				st.write({
					"source": m["source"],
					"sender": m.get("sender_address") or m.get("sender_display"),
					"received_at": m["received_at"],
					"ip": m.get("ip"),
					"device_fingerprint": m.get("device_fingerprint"),
					"keywords": m.get("keywords_hit"),
				})
				st.code(m.get("content") or "", language="text")
	else:
		st.info("No case selected or no cases yet.")

