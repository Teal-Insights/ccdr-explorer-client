from utils.chat.models import Node, ContentData, TagName, EmbeddingSource


def test_inline_bold_whitelist_without_db():
    node = Node(tag_name=TagName.P, sequence_in_parent=0)
    content = ContentData(
        node_id=1,
        text_content="<b>Clean cooking (CC)</b>",
        embedding_source=EmbeddingSource.TEXT_CONTENT,
    )
    node.content_data = content

    html = node.to_html(pretty=False)
    assert "<b>Clean cooking (CC)</b>" in html


