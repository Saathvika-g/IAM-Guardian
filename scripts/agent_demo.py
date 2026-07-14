#!/usr/bin/env python3
"""
IAM Guardian Agent Demo — runs a sequence of questions to demonstrate the agent.

Run with:
  python scripts/agent_demo.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv

load_dotenv()

from scripts.agent import run_query

DEMO_QUESTIONS = [
    "How many findings are in the database total?",
    "What HIGH severity findings exist?",
    "List all critical findings and explain why they are dangerous.",
    "Are there any open findings that haven't been remediated?",
    "What scans have been run and how many findings did each produce?",
    "Summarize the overall security posture based on the findings.",
]


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("IAM Guardian ReAct Agent — Demo Run")
    print("=" * 60)

    for index, question in enumerate(DEMO_QUESTIONS, 1):
        print(f"\n[{index}/{len(DEMO_QUESTIONS)}] {question}")
        print("-" * 50)
        answer = run_query(question)
        print(f"Answer: {answer}")
        print()
