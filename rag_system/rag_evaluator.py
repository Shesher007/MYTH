import asyncio
import logging
from typing import Any, Dict

from langchain_core.messages import HumanMessage
from langchain_nvidia_ai_endpoints import ChatNVIDIA

from myth_config import load_dotenv
from rag_system.rag_chain import RAGChain
from rag_system.vector_store import VectorStoreManager

# Load environment
load_dotenv()
from config_loader import agent_config  # noqa: E402

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAG_EVAL")


class RAGEvaluator:
    """Evaluates RAG system performance using LLM-as-a-judge"""

    def __init__(self, rag_chain: RAGChain, eval_llm: ChatNVIDIA):
        self.rag = rag_chain
        self.eval_llm = eval_llm

    async def evaluate_query(self, collection: str, question: str) -> Dict[str, Any]:
        """Evaluate a single query for faithfulness and relevance"""
        logger.info(f"Evaluating query: {question}")

        # 1. Get RAG Response
        response = await self.rag.create_qa_chain(collection).ainvoke(
            {"question": question}
        )
        answer = response.content if hasattr(response, "content") else str(response)

        # 2. Get retrieval context
        docs = await self.rag.vector_store.hybrid_search(collection, question, k=5)
        context = "\n\n".join([d["content"] for d in docs])

        # 3. Evaluate Faithfulness (Is the answer derived from context?)
        faithfulness_prompt = f"""
        Evaluate if the following answer is faithful to the provided context. 
        Only use the context to verify.
        
        Context: {context}
        Answer: {answer}
        
        Provide a score from 0 to 1 and a brief justification.
        Format: Score: [score] | Justification: [justification]
        """
        faithfulness_res = await self.eval_llm.ainvoke(
            [HumanMessage(content=faithfulness_prompt)]
        )

        # 4. Evaluate Answer Relevance (Does it answer the question?)
        relevance_prompt = f"""
        Evaluate if the following answer is relevant to the question.
        
        Question: {question}
        Answer: {answer}
        
        Provide a score from 0 to 1 and a brief justification.
        Format: Score: [score] | Justification: [justification]
        """
        relevance_res = await self.eval_llm.ainvoke(
            [HumanMessage(content=relevance_prompt)]
        )

        # 5. Evaluate Context Precision (How many retrieved docs are relevant?)
        precision_prompt = f"""
        Evaluate the Precision of the retrieved context. 
        Are the retrieved documents actually useful for answering the question?
        
        Question: {question}
        Context: {context}
        
        Score from 0 to 1 based on how many documents are relevant.
        Format: Score: [score] | Justification: [justification]
        """
        precision_res = await self.eval_llm.ainvoke(
            [HumanMessage(content=precision_prompt)]
        )

        # 6. Evaluate Context Recall (Is the information for the answer present in the context?)
        # This is tricky with LLM but we can ask if the context provides sufficient info.
        recall_prompt = f"""
        Evaluate the Recall of the retrieved context. 
        Does the context contain ALL the necessary information to answer the question?
        
        Question: {question}
        Context: {context}
        
        Score from 0 to 1.
        Format: Score: [score] | Justification: [justification]
        """
        recall_res = await self.eval_llm.ainvoke([HumanMessage(content=recall_prompt)])

        return {
            "question": question,
            "answer": answer,
            "faithfulness": faithfulness_res.content,
            "relevance": relevance_res.content,
            "context_precision": precision_res.content,
            "context_recall": recall_res.content,
            "num_sources": len(docs),
        }


async def main():
    from myth_config import config

    api_key = config.get_api_key("nvidia")
    # vsm = VectorStoreManager(persist_dir="chroma_db", nvidia_api_key=api_key) - OLD CHROMA CODE
    vsm = VectorStoreManager()  # Industrial In-Memory Initialization
    llm = ChatNVIDIA(model=agent_config.models.blueprint, nvidia_api_key=api_key)
    rag = RAGChain(vector_store_manager=vsm, llm=llm)

    eval_llm = ChatNVIDIA(model=agent_config.models.blueprint, nvidia_api_key=api_key)
    evaluator = RAGEvaluator(rag, eval_llm)

    collection = "security_docs"
    test_questions = [
        "What is CVE-2025-9999?",
        "How can I remediate SQL injection?",
        "Tell me about the latest security vulnerabilities.",
    ]

    for q in test_questions:
        result = await evaluator.evaluate_query(collection, q)
        print(f"\n--- Result for: {q} ---")
        print(f"Answer: {result['answer'][:200]}...")
        print(f"Faithfulness: {result['faithfulness']}")
        print(f"Relevance: {result['relevance']}")


if __name__ == "__main__":
    asyncio.run(main())
