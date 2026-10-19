"""search_knowledge: RAG over the organisation's policies, runbooks and past incidents (data/knowledge/*.md).

The whole pipeline, kept deliberately small:
  1. chunk    each document is split at its "## " headings: one section = one chunk, small enough to be specific
  2. embed    each chunk becomes a 384-number vector (BAAI/bge-small-en-v1.5, runs locally on the CPU via fastembed)
  3. store    vectors + text go into Qdrant (local in-memory mode: no server, rebuilt on first use)
  4. search   the question is embedded the same way; Qdrant returns the chunks with the highest cosine similarity

Logs and security events stay in Postgres with exact SQL tools; RAG is for questions about MEANING
("what does our policy say about legacy groups?"), where keyword or SQL matching doesn't work.
"""
from functools import cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, validate_call

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "data" / "knowledge"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
COLLECTION = "knowledge"
DocType = Literal["policy", "runbook", "incident"]


class KnowledgeChunk(BaseModel):
    source: str      # citable: "policy-penetration-testing#claims-of-testing-inside-data"
    doc_type: str
    title: str
    section: str
    text: str
    score: float     # cosine similarity to the question: 1.0 = same meaning, ~0 = unrelated


class KnowledgeResult(BaseModel):
    chunks: list[KnowledgeChunk]
    note: str = ("Organisational documents: use them to judge what the evidence means. They are guidance, not "
                 "evidence of what happened; cite them by source.")


def chunk_documents() -> list[dict]:
    """Split every document at its '## ' headings."""
    chunks = []
    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        lines = path.read_text().splitlines()
        title = lines[0].lstrip("# ").strip()
        section, body = None, []
        for line in lines[1:] + ["## <end>"]:
            if line.startswith("## "):
                if section and "".join(body).strip():
                    slug = "-".join(section.lower().replace(":", "").split())
                    chunks.append({"source": f"{path.stem}#{slug}", "doc_type": path.stem.split("-")[0],
                                   "title": title, "section": section, "text": " ".join(" ".join(body).split())})
                section, body = line[3:].strip(), []
            else:
                body.append(line)
    return chunks


@cache
def _embedder():
    from fastembed import TextEmbedding
    return TextEmbedding(EMBEDDING_MODEL)  # downloads the small model (~130 MB) on first use


@cache
def _index():
    """Build the vector index once per process: embed every chunk and store it in an in-memory Qdrant."""
    from qdrant_client import QdrantClient, models

    chunks = chunk_documents()
    # The section title is part of what gets embedded: it often carries the key words of the chunk
    vectors = list(_embedder().passage_embed([f"{c['title']}. {c['section']}. {c['text']}" for c in chunks]))
    client = QdrantClient(":memory:")
    client.create_collection(COLLECTION, vectors_config=models.VectorParams(size=len(vectors[0]),
                                                                            distance=models.Distance.COSINE))
    client.upsert(COLLECTION, points=[models.PointStruct(id=i, vector=v.tolist(), payload=c)
                                      for i, (c, v) in enumerate(zip(chunks, vectors))])
    return client


@validate_call
def search_knowledge(
    query: Annotated[str, Field(min_length=3, max_length=300)],
    doc_type: DocType | None = None,
    limit: Annotated[int, Field(ge=1, le=8)] = 4,
) -> KnowledgeResult:
    """Search the organisation's security policies, runbooks and past incident reports by meaning. Use it to
    check what the rules say about what you found (e.g. legacy access groups, MFA, penetration tests, bulk exports)
    and how similar incidents were handled. Optionally restrict to doc_type policy, runbook or incident."""
    from qdrant_client import models

    vector = list(_embedder().query_embed([query]))[0].tolist()
    query_filter = models.Filter(must=[models.FieldCondition(key="doc_type", match=models.MatchValue(value=doc_type))]) \
        if doc_type else None
    hits = _index().query_points(COLLECTION, query=vector, query_filter=query_filter, limit=limit).points
    return KnowledgeResult(chunks=[KnowledgeChunk(**hit.payload, score=round(hit.score, 3)) for hit in hits])
