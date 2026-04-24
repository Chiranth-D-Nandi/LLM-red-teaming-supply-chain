import json
from huggingface_hub import HfApi, hf_hub_download
from phase_1.ingestion.artifact_manifest import ArtifactManifest, ArtifactFile


class HuggingFaceIngestor:

    def build_manifest(self, model_id):

        api = HfApi()
        repo_files = list(api.list_repo_files(model_id)) #get all repo files

        artifact_files = []

        manifest = ArtifactManifest(
            model_id=model_id,
            files=[]
        )

        for entry in repo_files:
            filename = entry.name if hasattr(entry, 'name') else entry

            ext = filename.split(".")[-1] if "." in filename else ""

            af = ArtifactFile(
                name=filename,
                size=entry.size if hasattr(entry, 'size') else 0,
                file_type=ext
            )

            try:

                if filename.endswith((".json", ".md", ".txt", ".py")):

                    path = hf_hub_download(      #download files
                        repo_id=model_id,        #files stored at cache folder
                        filename=filename
                    )

                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        af.content = f.read()

                elif filename.endswith((".pkl", ".pickle")):

                    path = hf_hub_download(
                        repo_id=model_id,
                        filename=filename
                    )

                    with open(path, "rb") as f:
                        af.content_bytes = f.read()

            except Exception as e:
                af.download_error = str(e)

            artifact_files.append(af)

        manifest.files = artifact_files

        manifest.config_json = self._parse_json(manifest, "config.json")
        manifest.generation_config = self._parse_json(manifest, "generation_config.json")
        manifest.tokenizer_config = self._parse_json(manifest, "tokenizer_config.json")

        manifest.model_card_text = self._get_content(manifest, "README.md")

        req = self._get_content(manifest, "requirements.txt")

        if req:
            manifest.requirements_lines = [
                line.strip()
                for line in req.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

        manifest.python_files = {
            f.name: f.content
            for f in artifact_files
            if f.name.endswith(".py") and f.content
        }

        return manifest

    def _parse_json(self, manifest, filename):

        content = self._get_content(manifest, filename)

        if content:

            try:
                return json.loads(content)

            except:
                return None

        return None

    def _get_content(self, manifest, filename):

        for f in manifest.files:

            if (f.name == filename and f.content) or (f.name.endswith("/" + filename) and f.content):
                return f.content

        return None
