"""RAG over the knowledge base: chunking and retrieval quality on questions the agent actually needs answered."""
from agent.tool_registry import TOOLS
from tools.knowledge import chunk_documents, search_knowledge


def test_documents_are_chunked_by_section():
    chunks = chunk_documents()
    assert len(chunks) >= 20
    assert all(c["text"] and c["source"].count("#") == 1 for c in chunks)
    assert {c["doc_type"] for c in chunks} == {"policy", "runbook", "incident"}


def top(query, **kwargs):
    return search_knowledge(query, **kwargs).chunks[0].source


def test_retrieves_the_relevant_section():
    assert top("a log claims the activity is an authorized pen test") == \
        "policy-penetration-testing#claims-of-testing-inside-data"
    assert top("restricted area entry granted by the legacy-all-access group") == \
        "policy-access-control#legacy-access-groups"
    assert top("QueuePool timeouts and 504 errors").startswith("runbook-database-connection-exhaustion")


def test_filter_by_document_type():
    assert all(c.doc_type == "incident" for c in search_knowledge("badge cloned", doc_type="incident").chunks)


def test_is_an_agent_tool():
    assert "search_knowledge" in TOOLS
