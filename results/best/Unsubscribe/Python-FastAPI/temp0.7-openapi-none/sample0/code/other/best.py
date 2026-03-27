import email
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr

from fastapi import FastAPI, Request

"""Updated search in different keywords"""

app = FastAPI()

KEYWORD_PATTERNS = [
    re.compile(r'\bunsubscribe\b', re.IGNORECASE),
    re.compile(r'\bunsub\b', re.IGNORECASE),
    re.compile(r'\bremove\s+me\b', re.IGNORECASE),
    re.compile(r'\bderegister\s+me\b', re.IGNORECASE),
    re.compile(r'\bstop\s+sending\s+me\b', re.IGNORECASE),
    re.compile(r'\bdelete\s+me\b', re.IGNORECASE),
    re.compile(r'\bopt\s*out\b', re.IGNORECASE),
    re.compile(r'\bunsubscribe\s+me\b', re.IGNORECASE),
    re.compile(r'\bunsubscribe\s+from\s+this\s+list\b', re.IGNORECASE),
    re.compile(r'\bclick\s+here\s+to\s+unsubscribe\b', re.IGNORECASE),
]


def clean_html(html_text: str) -> str:
    return re.sub(r'<[^>]+>', ' ', html_text)


def contains_unsubscribe_intent(text: str) -> bool:
    for pattern in KEYWORD_PATTERNS:
        if pattern.search(text):
            return True
    return False


@app.post("/decideUnsubscribe")
async def decide_unsubscribe(request: Request):
    raw_email_bytes = await request.body()
    raw_email_str = raw_email_bytes.decode('utf-8')

    msg = email.message_from_string(raw_email_str, policy=policy.default)

    from_header = msg['From']
    name, email_address = parseaddr(from_header)

    unsubscribe = False

    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type in ('text/plain', 'text/html'):
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or 'utf-8'
                text = payload.decode(charset).lower()

                if content_type == 'text/html':
                    text = clean_html(text)

                if contains_unsubscribe_intent(text):
                    unsubscribe = True
                    break
            except Exception:
                pass

    return {
        "email": email_address,
        "unsubscribe": unsubscribe
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)