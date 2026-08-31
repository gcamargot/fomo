#!/usr/bin/env python3
"""
Single-Worker FIFO Queue for Automated AI Agent Triage
======================================================
Ensures only 1 Ollama LLM instance runs at any given time to protect local hardware
(VRAM/RAM/CPU). New triage requests are queued and processed sequentially.
"""

import os
import json
import queue
import threading
import requests
from datetime import datetime, timezone
from typing import Dict, Optional

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "triage-agent")
ENABLE_AI_TRIAGE = os.getenv("ENABLE_AI_TRIAGE", "true").lower() in ("true", "1", "yes")

# Thread-safe Single-Worker Task Queue
_triage_queue = queue.Queue()
_consumer_thread_started = False
_queue_lock = threading.Lock()

class AIAgentTriager:
    @staticmethod
    def is_ollama_available() -> bool:
        try:
            r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    @staticmethod
    def _start_consumer_if_needed():
        global _consumer_thread_started
        with _queue_lock:
            if not _consumer_thread_started:
                consumer_thread = threading.Thread(
                    target=AIAgentTriager._queue_consumer_loop,
                    daemon=True,
                    name="AI-Triage-Single-Worker"
                )
                consumer_thread.start()
                _consumer_thread_started = True

    @staticmethod
    def trigger_agent_triage_async(triage_file_path: str, contract_data: Dict):
        """
        Enqueues the triage card into the single-worker FIFO queue.
        Guarantees strict 1-at-a-time execution for local hardware limits.
        """
        if not ENABLE_AI_TRIAGE:
            return

        AIAgentTriager._start_consumer_if_needed()
        _triage_queue.put((triage_file_path, contract_data))
        qsize = _triage_queue.qsize()
        name = contract_data.get("name", "Unknown")
        print(f"[🤖 AI AGENT QUEUE] Enqueued {name} for sequential triage (Pending in Queue: {qsize})")

    @staticmethod
    def _queue_consumer_loop():
        """
        Dedicated single-worker daemon loop. Pops 1 task at a time.
        """
        while True:
            try:
                triage_file_path, contract_data = _triage_queue.get()
                AIAgentTriager._execute_triage(triage_file_path, contract_data)
                _triage_queue.task_done()
            except Exception as e:
                print(f"[🤖 AI AGENT QUEUE] Worker error: {e}")

    @staticmethod
    def _execute_triage(triage_file_path: str, contract_data: Dict):
        if not os.path.exists(triage_file_path):
            return

        addr = contract_data.get("address", "").lower()
        chain = contract_data.get("chain", "ethereum").lower()
        name = contract_data.get("name", "Unknown")

        print(f"\n[🤖 AI AGENT] [1/1 Active Worker] Starting triage for {name} (`{addr}`) on {chain.upper()}...")

        if not AIAgentTriager.is_ollama_available():
            print(f"[🤖 AI AGENT] Ollama service not reachable at {OLLAMA_HOST}. Skipping agent triage.")
            return

        try:
            with open(triage_file_path, "r", encoding="utf-8") as f:
                card_content = f.read()

            # Prevent duplicate reports if already appended
            if "Automated AI Agent Triage Report" in card_content:
                print(f"[🤖 AI AGENT] Card already triaged by agent. Skipping duplicate.")
                return

            prompt = (
                f"You have been assigned to review a newly detected vulnerability triage card.\n\n"
                f"TARGET CONTRACT: {name} (`{addr}`) on {chain.upper()}\n"
                f"TRIAGE CARD CONTENTS:\n"
                f"```markdown\n{card_content}\n```\n\n"
                f"Please conduct an executive triage assessment following your operational protocol:\n"
                f"1. Evaluate the code snippet and the invariant failure described.\n"
                f"2. Assess whether any operational mitigations (such as access modifiers, zero-balance state, DEX fee friction, or threshold multisigs) prevent immediate exploitation.\n"
                f"3. Provide a clear final classification: [True Positive - Active] vs [True Positive - Dormant/Mitigated] vs [False Positive].\n"
                f"4. Detail recommended defensive remediation for inclusion in the research dataset."
            )

            payload = {
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            }

            resp = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, timeout=300)
            if resp.status_code == 200:
                result_json = resp.json()
                agent_analysis = result_json.get("response", "").strip()

                timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                ai_section = (
                    f"\n\n---\n"
                    f"## 🤖 3. Automated AI Agent Triage Report\n"
                    f"**Agent Model:** `{OLLAMA_MODEL}`  \n"
                    f"**Triage Completed:** `{timestamp_str}`  \n\n"
                    f"{agent_analysis}\n"
                )

                with open(triage_file_path, "a", encoding="utf-8") as f:
                    f.write(ai_section)

                rem = _triage_queue.qsize()
                print(f"[🤖 AI AGENT] ✓ Completed triage for {name}! Report saved. (Remaining in queue: {rem})\n")
            else:
                print(f"[🤖 AI AGENT] Ollama error: HTTP {resp.status_code} - {resp.text}")

        except Exception as e:
            print(f"[🤖 AI AGENT] Exception during agent triage: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        card = sys.argv[1]
        AIAgentTriager.trigger_agent_triage_async(card, {"address": "manual", "chain": "test", "name": "ManualQueueTest"})
        _triage_queue.join()
    else:
        print("Usage: python3 ai_triage_agent.py <path_to_triage_card.md>")
