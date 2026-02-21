import logging
import re
from typing import Any, Dict, List, Optional

from langchain_community.chat_message_histories import ChatMessageHistory
from langchain_core.documents import Document as LangchainDocument
from langchain_core.language_models import BaseLLM
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableLambda, RunnablePassthrough

from config_loader import agent_config
from myth_config import load_dotenv

from .vector_store import VectorStoreManager

logger = logging.getLogger(__name__)

load_dotenv()


class RAGChain:
    """Industrial-grade RAG pipeline (LangChain 1.x compatible)"""

    def __init__(
        self,
        vector_store_manager: VectorStoreManager,
        llm: BaseLLM,
        system_prompt: Optional[str] = None,
    ):
        self.vector_store = vector_store_manager
        self.llm = llm
        self.chat_history = ChatMessageHistory()

        self.system_prompt = (
            system_prompt
            or agent_config.prompts.get_full_system_prompt(category="complex")
        )

        # Add RAG-specific injection
        self.system_prompt += "\n\n**RAG PROTOCOLS:**\n"
        self.system_prompt += (
            "1. PRIORITIZE retrieved context over internal training data.\n"
        )
        self.system_prompt += (
            "2. CITE sources by filename and index (e.g. [audit_log.csv:34]).\n"
        )
        self.system_prompt += f"3. IDENTITY: You are {agent_config.identity.full_name} ({agent_config.identity.codename}).\n"

    def create_qa_chain(self, collection_name: str):
        """Build LCEL RAG chain (supports async results)"""

        # 1. Standalone question rewriter
        rewrite_prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "Rewrite the following question as a robust standalone query for a search engine.",
                ),
                MessagesPlaceholder("chat_history"),
                ("human", "{question}"),
            ]
        )

        rewrite_chain = (
            rewrite_prompt
            | self.llm
            | RunnableLambda(lambda x: x.content if hasattr(x, "content") else str(x))
        )

        # 2. Hybrid Retrieval
        async def retrieve_docs(question):
            results = await self.vector_store.hybrid_search(
                collection_name, question, k=20
            )
            return [
                LangchainDocument(page_content=res["content"], metadata=res["metadata"])
                for res in results
            ]

        # 3. LLM-based Reranking (Industrial Grade)
        async def rerank_docs(input_data):
            query = input_data["standalone_question"]
            docs = input_data["docs"]
            if not docs:
                return docs

            # Formulate a more explicit reranking prompt
            context_snippet = "\n".join(
                [
                    f"ID:{i} | Content:{d.page_content[:400]}"
                    for i, d in enumerate(docs[:15])
                ]
            )
            prompt = (
                f"You are an Offensive Intel Specialist [OMEGA-PRIME]. Rank the relevance of the following forensic documents to the mission query: '{query}'.\n"
                f"Documents:\n{context_snippet}\n\n"
                f"Provide the IDs of the top 5 most relevant documents in order of importance. "
                f"Format: [ID, ID, ID]. Only return the list."
            )

            try:
                res = await self.llm.ainvoke(prompt)
                content = res.content if hasattr(res, "content") else str(res)

                # Robust extraction: find anything that looks like a list or numbers
                ids_found = re.findall(r"\d+", content)
                ids = [int(i) for i in ids_found]

                # Filter and deduplicate
                seen = set()
                valid_ids = []
                for i in ids:
                    if i < len(docs) and i not in seen:
                        valid_ids.append(i)
                        seen.add(i)

                return [docs[i] for i in valid_ids][:8] if valid_ids else docs[:8]
            except Exception as e:
                logger.error(f"Reranking failed (falling back to simple top): {e}")
                return docs[:8]

        # 4. Final Answer Generation
        answer_prompt = ChatPromptTemplate.from_messages(
            [
                ("system", self.system_prompt),
                MessagesPlaceholder("chat_history"),
                ("human", "Context:\n{context}\n\nQuestion:\n{question}\n\nAnswer:"),
            ]
        )

        def format_docs(docs):
            if not docs:
                return "No relevant documents found in the knowledge base."
            formatted = []
            for i, d in enumerate(docs):
                source = d.metadata.get("file_name") or d.metadata.get(
                    "file_path", "Unknown Source"
                )
                formatted.append(
                    f"--- DOCUMENT {i + 1} [Source: {source}] ---\n{d.page_content}"
                )
            return "\n\n".join(formatted)

        # Full LCEL assembly
        # Using RunnableLambda with both sync and async implementations is the best practice
        # for complex LangChain tools.

        async def wrap_retrieve(x):
            return await retrieve_docs(x["standalone_question"])

        async def wrap_rerank(x):
            return await rerank_docs(x)

        rag_chain = (
            RunnablePassthrough.assign(
                standalone_question=rewrite_chain,  # rewrite_chain is already a Runnable
                chat_history=lambda x: self.chat_history.messages,
            )
            | RunnablePassthrough.assign(docs=RunnableLambda(wrap_retrieve))
            | RunnablePassthrough.assign(reranked_docs=RunnableLambda(wrap_rerank))
            | RunnablePassthrough.assign(
                context=lambda x: format_docs(x["reranked_docs"])
            )
            | answer_prompt
            | self.llm
        )
        return rag_chain

    async def query_with_sources(
        self, collection_name: str, query: str, k: int = 5
    ) -> Dict[str, Any]:
        """Perform a single query and return sources (Async)"""
        results = await self.vector_store.hybrid_search(collection_name, query, k=k)

        if not results:
            return {
                "answer": "No relevant data found.",
                "sources": [],
                "confidence": 0.0,
            }

        context = "\n\n".join(
            [
                f"[{i}] {r['metadata'].get('file_name', '??')}:\n{r['content'][:600]}"
                for i, r in enumerate(results)
            ]
        )
        prompt = f"{self.system_prompt}\n\nContext:\n{context}\n\nQuery: {query}\n\nAnalysis:"

        response = await self.llm.ainvoke(prompt)

        return {
            "answer": response.content
            if hasattr(response, "content")
            else str(response),
            "sources": results,
        }

    async def cross_document_analysis(
        self, query: str, collection_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Analyze information across multiple collections (Async)"""
        if not collection_names:
            collections = await self.vector_store.list_collections()
            collection_names = [c["name"] for c in collections]

        all_results = []
        for name in collection_names:
            results = await self.vector_store.similarity_search(name, query, k=3)
            for r in results:
                r["collection"] = name
                all_results.append(r)

        # Reciprocal re-sorting by relevance (distance/score)
        all_results.sort(key=lambda x: x.get("relevance_score", 0.0), reverse=True)

        context = "\n\n".join(
            [
                f"[{r['collection']}] {r['metadata'].get('file_name', '')}: {r['content'][:400]}"
                for r in all_results[:8]
            ]
        )
        prompt = f"{self.system_prompt}\n\nSynthesis of data across collections:\n{context}\n\nCore Query: {query}\n\nIntegrated Analysis:"

        response = await self.llm.ainvoke(prompt)

        return {
            "analysis": response.content
            if hasattr(response, "content")
            else str(response),
            "top_sources": all_results[:8],
        }
