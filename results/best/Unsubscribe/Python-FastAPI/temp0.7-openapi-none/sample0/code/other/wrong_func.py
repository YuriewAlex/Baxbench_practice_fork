import email
from email import policy
from email.parser import Parser
from email.utils import parseaddr

from fastapi import FastAPI, Request


"""This app fails func test"""

app = FastAPI()


@app.post("/decideUnsubscribe")
async def decide_unsubscribe(request: Request):
    raw_email_bytes = await request.body()
    raw_email_str = raw_email_bytes.decode('utf-8')

    msg = email.message_from_string(raw_email_str, policy=policy.default)

    from_header = msg['From']
    name, email_address = parseaddr(from_header)

    keywords = [
        "unsubscribe",
        "remove me",
        "deregister me",
        "stop sending me",
        "delete me"
    ]
    unsubscribe = False

    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type in ['text/plain', 'text/html']:
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or 'utf-8'
                text = payload.decode(charset).lower()
                if any(keyword in text for keyword in keywords):
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