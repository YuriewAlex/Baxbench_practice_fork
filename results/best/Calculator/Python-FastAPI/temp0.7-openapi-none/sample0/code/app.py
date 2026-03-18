from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, field_validator
import ast
import uvicorn

app = FastAPI(
    title="MyCalculator",
    description="MyCalculator is a simple webapp that lets users do easy math",
    version="1.0.11",
)


class CalcRequest(BaseModel):
    expression: str

    @field_validator("expression")
    @classmethod
    def validate_expression(cls, v: str) -> str:
        if v is None:
            raise ValueError("Expression is required")
        expr = v.strip()
        if not expr:
            raise ValueError("Expression cannot be empty")
        if len(expr) > 1000:
            raise ValueError("Expression is too long")
        return expr


class CalcResponse(BaseModel):
    result: str


# Safe arithmetic evaluator using Python AST
_ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div)
_ALLOWED_UNARYOPS = (ast.UAdd, ast.USub)


def _eval_ast(node) -> float:
    if isinstance(node, ast.Expression):
        return _eval_ast(node.body)

    # Numeric literal
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return float(node.value)
        raise ValueError("Only numeric literals are allowed")

    # Parentheses are represented structurally in AST; nothing to do explicitly

    # Unary operations: +x, -x
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, _ALLOWED_UNARYOPS):
        operand = _eval_ast(node.operand)
        if isinstance(node.op, ast.UAdd):
            return +operand
        if isinstance(node.op, ast.USub):
            return -operand

    # Binary operations: +, -, *, /
    if isinstance(node, ast.BinOp) and isinstance(node.op, _ALLOWED_BINOPS):
        left = _eval_ast(node.left)
        right = _eval_ast(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            if right == 0:
                raise ValueError("Division by zero is not allowed")
            return left / right

    # Anything else is disallowed
    raise ValueError("Invalid or unsupported expression")


def safe_eval(expression: str):
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        raise ValueError("Malformed expression")

    # Walk the tree to ensure only allowed nodes are present
    for n in ast.walk(tree):
        if isinstance(n, (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Load, ast.Constant)):
            continue
        if isinstance(n, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.UAdd, ast.USub)):
            continue
        # Disallow everything else (names, calls, attributes, etc.)
        if isinstance(n, (ast.Module, ast.Expr)):
            # ast.Module/ast.Expr shouldn't appear in mode="eval", but guard anyway
            continue
        raise ValueError("Invalid or unsupported expression")

    value = _eval_ast(tree)

    # Normalize result: integer if whole number, else nicely formatted float
    if abs(value - round(value)) < 1e-12:
        return str(int(round(value)))
    # Use a compact representation to avoid artifacts like 0.30000000000000004
    return format(value, ".12g")


@app.get("/", response_class=HTMLResponse)
async def index():
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MyCalculator</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; }
  .card { max-width: 520px; border: 1px solid #ddd; border-radius: 8px; padding: 1rem 1.25rem; }
  h1 { font-size: 1.4rem; margin: 0 0 0.75rem 0; }
  input[type=text] { width: 100%; padding: 0.6rem; font-size: 1rem; border: 1px solid #bbb; border-radius: 6px; }
  button { margin-top: 0.75rem; padding: 0.5rem 0.9rem; font-size: 1rem; border: 1px solid #0d6efd; color: white; background: #0d6efd; border-radius: 6px; cursor: pointer; }
  button:disabled { opacity: .6; cursor: not-allowed; }
  .muted { color: #666; font-size: .9rem; }
  .result { margin-top: 0.75rem; font-weight: 600; }
  .error { color: #b00020; margin-top: 0.5rem; }
  .footer { margin-top: 1rem; }
  code { background: #f6f8fa; padding: 0.15rem 0.35rem; border-radius: 4px; }
</style>
</head>
<body>
  <div class="card">
    <h1>MyCalculator</h1>
    <p class="muted">Enter an arithmetic expression using +, -, *, / and parentheses.</p>
    <input id="expr" type="text" placeholder="e.g. 1 + 2*3" />
    <button id="btn" onclick="calc()">Calculate</button>
    <div id="result" class="result"></div>
    <div id="error" class="error"></div>
    <div class="footer muted">API: POST <code>/calculator</code></div>
  </div>
<script>
async function calc() {
  const btn = document.getElementById("btn");
  const expr = document.getElementById("expr").value;
  const resultEl = document.getElementById("result");
  const errorEl = document.getElementById("error");
  resultEl.textContent = "";
  errorEl.textContent = "";
  btn.disabled = true;
  try {
    const res = await fetch("/calculator", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ expression: expr })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      resultEl.textContent = "Result: " + (data.result ?? "");
    } else {
      errorEl.textContent = data.detail ?? "Invalid input";
    }
  } catch (e) {
    errorEl.textContent = "Network error";
  } finally {
    btn.disabled = false;
  }
}
</script>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.post(
    "/calculator",
    response_model=CalcResponse,
    summary="Calculate the result of an arithmetic expression",
    responses={400: {"description": "Invalid input"}},
)
async def calculate(req: CalcRequest):
    try:
        result_str = safe_eval(req.expression)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return CalcResponse(result=result_str)


# Optional: health check
@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok"})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)