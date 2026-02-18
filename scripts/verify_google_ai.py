
import os
import sys

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    print("✅ Successfully imported langchain_google_genai")
except ImportError as e:
    print(f"❌ Failed to import langchain_google_genai: {e}")
    sys.exit(1)

try:
    # Attempt instantiation with dummy key (should fail only on invocation, or pass if no immediate validation)
    llm = ChatGoogleGenerativeAI(google_api_key="dummy_key", model="gemini-pro")
    print(f"✅ Successfully instantiated ChatGoogleGenerativeAI(model='gemini-pro')")
except Exception as e:
    print(f"❌ Failed to instantiate: {e}")
    sys.exit(1)

print("✨ Google AI Provider verification complete.")
