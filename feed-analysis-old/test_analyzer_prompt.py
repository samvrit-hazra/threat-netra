import os
import json
import asyncio
from dotenv import load_dotenv
load_dotenv("/home/samvrit/Desktop/Threat Intel/.env")
from groq import Groq

feeds = [{"title": "Iran war news LIVE: Tensions escalate", "description": "Tensions rise today."}]
scenarios = ["the war has ended"]

prompt = f"""
You are an autonomous Cyber Threat Intelligence (CTI) analyst engine.
Read the feed items and determine if they EXPLICITLY state that a user scenario has occurred.

User Custom Scenarios to Alert On: {json.dumps(scenarios)}

RULES FOR SCENARIO MATCHING:
1. Read the article title and description.
2. Does it EXPLICITLY and CLEARLY state that the scenario happened? 
3. If it only talks about related topics (like "war" or "tensions") but does NOT say it ended, then it is NOT a match.
4. "is_scenario_match" MUST be false unless the exact event occurred.

Raw Feed Items:
{json.dumps(feeds)}

Respond ONLY with a valid JSON object containing a single key "analysis" which holds an array of objects.
Structure:
{{
    "analysis": [
        {{
            "item_title": "Original title of the item",
            "reasoning": "Explain step-by-step why it does or does not match.",
            "is_scenario_match": true or false,
            "matched_scenario_name": "If true, put the scenario name here. If false, put exactly 'None'.",
            "summary": "A brief 1-2 sentence cyber threat intelligence summary of the item."
        }}
    ]
}}
"""

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
try:
    print("Testing prompt...")
    res = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="allam-2-7b",
        temperature=0.0,
        response_format={"type": "json_object"}
    )
    print(res.choices[0].message.content)
except Exception as e:
    print("ERROR:", e)

