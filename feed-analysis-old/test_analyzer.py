import asyncio
from dotenv import load_dotenv
load_dotenv("/home/samvrit/Desktop/Threat Intel/.env")

from app.services.fetcher import fetch_bing
from app.services.analyzer import analyze_with_groq

async def test():
    print("Fetching bing news for 'iran war'...")
    feeds = await fetch_bing("iran war", 3)
        
    print("\nRunning Groq analysis for scenario: 'the war has ended'...")
    scenarios = ["the war has ended"]
    results = analyze_with_groq(feeds, scenarios)
    
    print("RESULTS:")
    print(results)

if __name__ == "__main__":
    asyncio.run(test())
