# services/semantic_search.py
from typing import List, Optional, TypedDict, Iterable, Annotated
import warnings
from sqlmodel import Session, text, select
from openai import OpenAI
from pydantic import Field
from utils.core.db import engine
from utils.chat.models import Node, TagName, SectionType, ISO3Country, GeoAggregate
from utils.chat.function_calling import Context


class SearchResult(TypedDict):
    node_id: int
    document_id: int
    publication_id: Optional[int]
    similarity: float
    html: str
    citation: str

class ContextResult(TypedDict):
    node_id: int
    parent_node_id: int
    document_id: int
    publication_id: Optional[int]
    html: str
    citation: str


def embed_query(query: str, *, model: str = "text-embedding-3-small") -> List[float]:
    # Use your OPENAI_API_KEY in env
    client = OpenAI()
    try:
        emb = client.embeddings.create(model=model, input=query)
        return emb.data[0].embedding  # List[float]
    finally:
        client.close()


# TODO: Replace tag_names and section_types with include and exclude, each a union of TagName and SectionType?
def semantic_search(
    query_text: Annotated[str, Field(description="The query text to embed and search for.")],
    *,
    top_k: Annotated[int, Field(description="Maximum number of results to return.", ge=1)] = 10,
    document_ids: Annotated[Optional[Iterable[int]], Field(description="Filter results to these document IDs.")] = None,
    publication_ids: Annotated[Optional[Iterable[int]], Field(description="Filter results to these publication IDs.")] = None,
    tag_names: Annotated[Optional[Iterable[str]], Field(description=f"Filter by node tag names. Any of {", ".join(TagName.__members__.keys())}.")] = None,
    section_types: Annotated[Optional[Iterable[str]], Field(description=f"Filter by node section types. Any of {", ".join(SectionType.__members__.keys())}.")] = None,
    geographies: Annotated[
        Optional[Iterable[str]],
        Field(description=f"Filter by ISO3 country codes or geographic aggregates (e.g., continent:AF). Any of {", ".join(ISO3Country.__members__.keys())} or {", ".join(GeoAggregate.__members__.keys())}."),
    ] = None,
    context: Optional[Context] = None
) -> List[SearchResult]:
    """Perform a semantic (cosine similarity) search over content-bearing HTML nodes in the CCDR corpus."""
    session: Session
    if context and context.session:
        session = context.session
    else:
        session = Session(engine)

    qvec = embed_query(query_text, model="text-embedding-3-small")

    # NOTE: Uses pgvector cosine distance operator in ORDER BY.
    # If your column type is `vector`, this works as-is.
    # If your column is float[] in the DB, adjust migration to vector or cast appropriately.
    sql = """
        SELECT
        e.id AS embedding_id,
        cd.id AS content_data_id,
        n.id AS node_id,
        n.document_id AS document_id,
        d.publication_id AS publication_id,
        (e.embedding_vector <=> ((:qvec)::double precision[]::vector(1536))) AS distance
        FROM embedding e
        JOIN contentdata cd ON cd.id = e.content_data_id
        JOIN node n ON n.id = cd.node_id
        JOIN document d ON d.id = n.document_id
        LEFT JOIN publication p ON p.id = d.publication_id
        WHERE 1=1
        -- dynamic filters below
        {doc_filter}
        {pub_filter}
        {tag_filter}
        {sect_filter}
        {geog_filter}
        ORDER BY e.embedding_vector <=> ((:qvec)::double precision[]::vector(1536))
        LIMIT :top_k
    """

    def make_filter(column: str, values: Optional[Iterable]) -> tuple[str, dict]:
        if values:
            return f"AND {column} = ANY(:{column}_arr)", {f"{column}_arr": list(values)}
        return "", {}

    doc_sql, doc_params = make_filter("n.document_id", document_ids)
    pub_sql, pub_params = make_filter("d.publication_id", publication_ids)

    tag_sql, tag_params = ("", {})
    invalid_tag_names: List[str] = []
    if tag_names:
        valid_tag_values: List[str] = []
        for t in tag_names:
            if t.lower() in TagName.__members__:
                valid_tag_values.append(t.lower())
            else:
                invalid_tag_names.append(t)
        if valid_tag_values:
            tag_sql = "AND n.tag_name = ANY(:tag_name_arr)"
            tag_params = {"tag_name_arr": valid_tag_values}

    sect_sql, sect_params = ("", {})
    invalid_section_types: List[str] = []
    if section_types:
        valid_section_values: List[str] = []
        for s in section_types:
            if s.upper() in SectionType.__members__:
                valid_section_values.append(s.upper())
            else:
                invalid_section_types.append(s)
        if valid_section_values:
            sect_sql = "AND n.section_type = ANY(:section_type_arr)"
            sect_params = {"section_type_arr": valid_section_values}

    # Geography filter: split inputs into ISO3 codes vs aggregates
    geog_sql, geog_params = ("", {})
    if geographies:
        iso3_list: List[str] = []
        agg_list: List[str] = []

        iso3_values = {c.value for c in ISO3Country}

        for g in geographies:
            value = getattr(g, "value", g)
            if isinstance(value, str):
                if value.upper() in iso3_values:
                    iso3_list.append(value.upper())
                else:
                    agg_list.append(value)
        # Deduplicate preserving order
        iso3_list = list(dict.fromkeys(iso3_list))
        agg_list = list(dict.fromkeys(agg_list))

        geog_clauses: List[str] = []
        if iso3_list:
            geog_clauses.append(
                "EXISTS (\n"
                "  SELECT 1 FROM jsonb_array_elements_text(p.publication_metadata->'geographical'->'iso3_country_codes') iso(code)\n"
                "  WHERE iso.code = ANY(:iso3_arr)\n"
                ")"
            )
        if agg_list:
            geog_clauses.append(
                "EXISTS (\n"
                "  SELECT 1 FROM jsonb_array_elements_text(p.publication_metadata->'geographical'->'aggregates') agg(val)\n"
                "  WHERE agg.val = ANY(:agg_arr)\n"
                ")"
            )
        if geog_clauses:
            geog_sql = "AND ( " + " OR ".join(geog_clauses) + " )"
            if iso3_list:
                geog_params["iso3_arr"] = iso3_list
            if agg_list:
                geog_params["agg_arr"] = agg_list

    rendered = sql.format(
        doc_filter=doc_sql,
        pub_filter=pub_sql,
        tag_filter=tag_sql,
        sect_filter=sect_sql,
        geog_filter=geog_sql,
    )

    params = {
        "qvec": qvec,
        "top_k": top_k,
        **doc_params,
        **pub_params,
        **tag_params,
        **sect_params,
        **geog_params,
    }

    rows = session.exec(text(rendered), params=params).mappings().all()

    # Load nodes and render HTML
    node_ids = [r["node_id"] for r in rows]
    nodes_by_id = {}
    if node_ids:
        nodes = session.exec(select(Node).where(Node.id.in_(node_ids))).all()
        nodes_by_id = {n.id: n for n in nodes}

    results: List[SearchResult] = []
    for r in rows:
        node = nodes_by_id.get(r["node_id"])
        html = node.to_html(
            include_citation_data=False,
            pretty=False,
        ) if node else ""
        dist = float(r["distance"])
        results.append(SearchResult(
            node_id=int(r["node_id"]),
            document_id=int(r["document_id"]),
            publication_id=int(r["publication_id"]) if r["publication_id"] is not None else None,
            similarity=1.0 - dist,  # cosine distance -> similarity
            html=html,
            citation=node.get_citation() if node else "",
        ))
    if not results:
        warnings.warn("No results found")
    if invalid_tag_names:
        warnings.warn("Ignored invalid tag_names: " + ", ".join(invalid_tag_names))
    if invalid_section_types:
        warnings.warn("Ignored invalid section_types: " + ", ".join(invalid_section_types))
    
    if not (context and context.session):
        session.close()

    return results


def render_context(
    node_id: Annotated[int, Field(description="ID of the HTML node to render in context.")],
    *,
    pretty: Annotated[bool, Field(description="Pretty-print the HTML output with indentation.")] = True,
    separator: Annotated[str, Field(description="String used to separate sections of the rendered context.")] = "\n",
    context: Optional[Context] = None
) -> Optional[ContextResult]:
    """Render the HTML node in its parent context (e.g., the containing table, figure, or section)."""
    session: Session
    if context and context.session:
        session = context.session
    else:
        session = Session(engine)
    try:
        node = session.get(Node, node_id)
        if not node:
            warnings.warn("Node not found")
            return None
        html = node.render_context_html(
            session,
            node_id,
            include_citation_data=False,
            pretty=pretty,
            separator=separator,
        )
        if not html:
            warnings.warn("Node not found or no context available")
        return ContextResult(
            node_id=node.id,
            parent_node_id=node.parent_id,
            document_id=node.document_id,
            publication_id=node.document.publication_id,
            html=html,
            citation=node.get_citation(),
        )
    finally:
        if not (context and context.session):
            session.close()