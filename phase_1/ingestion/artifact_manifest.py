from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass     #decorator to automatically generate special methods like __init__() and __repr__()
class ArtifactFile: #this is for each file in the repo
    name: str
    size: int
    file_type: str
    content: Optional[str] = None
    content_bytes: Optional[bytes] = None
    download_error: Optional[str] = None


@dataclass
class ArtifactManifest:
    model_id: str
    files: List[ArtifactFile]

    config_json: Optional[Dict] = None
    generation_config: Optional[Dict] = None
    tokenizer_config: Optional[Dict] = None
    model_card_text: Optional[str] = None
    requirements_lines: Optional[List[str]] = None
    python_files: Dict[str, str] = field(default_factory=dict)
