"""Bounded, in-memory source extraction. No uploaded code is executed."""

import io
import json
import zipfile
from pathlib import PurePath

from analyzer import validate_source

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_EXPANDED_DOCX_BYTES = 20 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".cpp", ".cc", ".h", ".hpp", ".c", ".cs",
    ".php", ".html", ".css", ".sql", ".sh", ".bat", ".txt", ".json", ".xml", ".yaml", ".yml",
    ".ipynb", ".pdf", ".docx",
}


def process_file(data, filename):
    ext = PurePath(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file type. Upload source, PDF, DOCX or a Jupyter notebook.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload exceeds the 5 MB limit.")
    kind = "source"
    try:
        if ext == ".pdf":
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data))
            if reader.is_encrypted:
                raise ValueError("Encrypted PDFs are not supported. Upload an unlocked document or source file.")
            if len(reader.pages) > 100:
                raise ValueError("PDF exceeds 100 pages. Upload a smaller document.")
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            kind = "document"
        elif ext == ".docx":
            import docx
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if sum(item.file_size for item in archive.infolist()) > MAX_EXPANDED_DOCX_BYTES:
                    raise ValueError("DOCX expanded contents exceed the 20 MB limit.")
            document = docx.Document(io.BytesIO(data))
            # iter_inner_content preserves paragraphs/tables in document order.
            chunks = []
            for block in document.iter_inner_content():
                if hasattr(block, "rows"):
                    chunks.extend("\t".join(cell.text for cell in row.cells) for row in block.rows)
                else:
                    chunks.append(block.text)
            text = "\n".join(chunks)
            kind = "document"
        else:
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise ValueError("Source files must be UTF-8 text. Convert the encoding before uploading.") from None
            if ext == ".ipynb":
                notebook = json.loads(text)
                cells = notebook["cells"]
                if not isinstance(cells, list):
                    raise ValueError("Invalid notebook cells.")
                text = "\n\n".join("".join(cell.get("source", [])) for cell in cells if cell.get("cell_type") == "code")
                kind = "notebook"
        validate_source(text)
        return text, kind
    except ValueError:
        raise
    except Exception:
        raise ValueError("Could not extract this file. Upload a valid source file or a readable, unencrypted document.") from None
