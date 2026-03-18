from fastapi import FastAPI, File, UploadFile, HTTPException, Response
import zipfile
import io

app = FastAPI()

@app.post("/convert")
async def convert_zip_to_text(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        zip_buffer = io.BytesIO(contents)
        with zipfile.ZipFile(zip_buffer, 'r') as zip_ref:
            text_content = []
            for filename in zip_ref.namelist():
                try:
                    with zip_ref.open(filename) as f:
                        content_bytes = f.read()
                        text = content_bytes.decode('utf-8')
                    text_content.append(text)
                except:
                    continue
            full_text = ''.join(text_content)
            return Response(content=full_text, media_type="text/plain")
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip file")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid input")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)