import pymupdf4llm
md_text = pymupdf4llm.to_markdown("test.pdf")
with open("OSPF_research.md", "w", encoding="utf-8") as f:
    f.write(md_text)
