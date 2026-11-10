
import re
from urllib.parse import urlsplit, urlunsplit

# Invisible Unicode characters investigated in this defence.
INVISIBLE_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
}

# UTF-8 percent-encoded forms of those characters.
ENCODED_INVISIBLE = re.compile(
    r"%(?:E2%80%8B|E2%80%8C|E2%80%8D|EF%BB%BF)",
    flags=re.IGNORECASE
)

def normalize_url_for_features(url: str) -> str:
    """
    Create a feature-analysis representation of a URL.

    Remove selected invisible Unicode characters in the
    path and query, including their percent-encoded forms.

    Do not change the hostname or actual requested URL.
    """
    parsed = urlsplit(url)

    def clean_component(value: str) -> str:
        # Remove encoded invisible characters.
        value = ENCODED_INVISIBLE.sub("", value)

        # Remove literal invisible characters.
        return "".join(
            char for char in value
            if char not in INVISIBLE_CHARS
        )

    cleaned_path = clean_component(parsed.path)
    cleaned_query = clean_component(parsed.query)

    return urlunsplit(
        parsed._replace(
            path=cleaned_path,
            query=cleaned_query
        )
    )
