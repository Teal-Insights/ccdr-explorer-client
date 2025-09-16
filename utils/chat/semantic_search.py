# services/semantic_search.py
from typing import List, Optional, TypedDict, Iterable, Union, Annotated
from sqlmodel import Session, text, select
from openai import OpenAI
from pydantic import Field
from utils.core.db import engine
from utils.chat.models import Node, TagName, SectionType, ISO3Country, GeoAggregate

class SearchResult(TypedDict):
    node_id: int
    document_id: int
    publication_id: Optional[int]
    distance: float
    similarity: float
    html: str


def embed_query(query: str, *, model: str = "text-embedding-3-small") -> List[float]:
    # Use your OPENAI_API_KEY in env
    client = OpenAI()
    emb = client.embeddings.create(model=model, input=query)
    return emb.data[0].embedding  # List[float]


def semantic_search(
    query_text: Annotated[str, Field(description="The query text to embed and search for.")],
    *,
    top_k: Annotated[int, Field(description="Maximum number of results to return.", ge=1)] = 10,
    document_ids: Annotated[Optional[Iterable[int]], Field(description="Filter results to these document IDs.")] = None,
    publication_ids: Annotated[Optional[Iterable[int]], Field(description="Filter results to these publication IDs.")] = None,
    tag_names: Annotated[Optional[Iterable[TagName]], Field(description="Filter by node tag names.")] = None,
    section_types: Annotated[Optional[Iterable[SectionType]], Field(description="Filter by node section types.")] = None,
    include_citation_data: Annotated[bool, Field(description="Include citation metadata in rendered HTML.")] = True,
    geographies: Annotated[
        Optional[Iterable[Union[str, ISO3Country, GeoAggregate]]],
        Field(description="Filter by ISO3 country codes or geographic aggregates (e.g., continent:AF)."),
    ] = None,
) -> List[SearchResult]:
    """Perform a semantic (cosine similarity) search over content-bearing HTML nodes in the CCDR corpus."""
    with Session(engine) as session:
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
        if tag_names:
            tag_sql = "AND n.tag_name = ANY(:tag_name_arr)"
            tag_params = {"tag_name_arr": list(tag_names)}

        sect_sql, sect_params = ("", {})
        if section_types:
            sect_sql = "AND n.section_type = ANY(:section_type_arr)"
            sect_params = {"section_type_arr": list(section_types)}

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
                include_citation_data=include_citation_data,
                pretty=False,
            ) if node else ""
            dist = float(r["distance"])
            results.append({
                "node_id": int(r["node_id"]),
                "document_id": int(r["document_id"]),
                "publication_id": int(r["publication_id"]) if r["publication_id"] is not None else None,
                "distance": dist,
                "similarity": 1.0 - dist,  # cosine distance -> similarity
                "html": html,
            })
    return results


def render_context(
    node_id: Annotated[int, Field(description="ID of the HTML node to render in context.")],
    *,
    include_citation_data: Annotated[bool, Field(description="Include citation metadata in the rendered HTML.")] = True,
    pretty: Annotated[bool, Field(description="Pretty-print the HTML output with indentation.")] = True,
    separator: Annotated[str, Field(description="String used to separate sections of the rendered context.")] = "\n",
) -> Optional[str]:
    """Render the HTML node in its parent context (e.g., the containing table, figure, or section)."""
    with Session(engine) as session:
        return Node.render_context_html(
            session,
            node_id,
            include_citation_data=include_citation_data,
            pretty=pretty,
            separator=separator,
        )
