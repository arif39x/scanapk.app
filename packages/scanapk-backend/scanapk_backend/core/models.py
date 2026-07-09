import os

MODELS = [
    {"name": "gpt-oss-20b", "key_env": "OPENROUTER_API_KEY"},
    {"name": "google/gemma-4-31b-it", "key_env": "OPENROUTER_API_KEY_BACKUP1"},
    {"name": "gpt-oss-120b", "key_env": "OPENROUTER_API_KEY_BACKUP2"},
]


def get_models() -> list[tuple[str, str]]:
    return [(m["name"], m["key_env"]) for m in MODELS if os.environ.get(m["key_env"])]
