
from io import BytesIO
from pathlib import PurePath

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from phishguard.analyzers import (
    analyze_url,
    analyze_eml,
    analyze_qr,
    analyze_file_bytes,
    analyze_social,
)

from backend.report_generator import (
    generate_url_report,
    generate_email_report,
    generate_qr_report,
    generate_file_report,
    generate_social_report,
)


# ==========================================
# FASTAPI APPLICATION
# ==========================================

app = FastAPI(
    title="PhishGuard API",
    description="Multi-Channel Phishing Investigation Platform",
    version="0.1.0",
)


# ==========================================
# CORS CONFIGURATION
# ==========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ==========================================
# CONFIGURATION
# ==========================================

MIB = 1024 * 1024

MAX_EMAIL_SIZE = 10 * MIB
MAX_QR_SIZE = 10 * MIB
MAX_FILE_SIZE = 25 * MIB

QR_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".bmp",
)


# ==========================================
# REQUEST MODELS
# ==========================================

class URLAnalysisRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=2048,
    )


class SocialAnalysisRequest(BaseModel):
    text: str = Field(
        min_length=1,
        max_length=50000,
    )

    platform: str = Field(
        default="",
        max_length=100,
    )


# ==========================================
# COMMON ANALYSIS ENGINE
# ==========================================

def run_analysis(analyzer, *args, **kwargs):
    try:
        result = analyzer(
            *args,
            use_intel=False,
            online=False,
            **kwargs,
        )

        if result.error:
            raise HTTPException(
                status_code=422,
                detail=result.error,
            )

        return result

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Analysis failed.",
        ) from exc


# ==========================================
# COMMON PDF GENERATOR
# ==========================================

def create_pdf(generator, result, name):
    try:
        pdf_bytes = generator(result)

        return StreamingResponse(
            BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition":
                    f'attachment; filename="PhishGuard_{name}_Report.pdf"',
                "Cache-Control": "no-store",
            },
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="PDF report generation failed.",
        ) from exc


# ==========================================
# FILE UPLOAD VALIDATION
# ==========================================

async def process_upload(
    file,
    analyzer,
    limit,
    extensions=None,
    **kwargs,
):
    try:
        filename = PurePath(
            (file.filename or "upload.bin")
            .replace("\\", "/")
        ).name

        if extensions:
            if not filename.lower().endswith(extensions):
                raise HTTPException(
                    status_code=400,
                    detail="Unsupported file extension.",
                )

        data = await file.read(limit + 1)

        if not data:
            raise HTTPException(
                status_code=400,
                detail="The uploaded file is empty.",
            )

        if len(data) > limit:
            raise HTTPException(
                status_code=413,
                detail="Upload exceeds the allowed size limit.",
            )

        return await run_in_threadpool(
            run_analysis,
            analyzer,
            data,
            filename=filename,
            **kwargs,
        )

    finally:
        await file.close()


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "PhishGuard API",
        "version": "0.1.0",
    }


# ==========================================
# 01. URL ANALYZER
# ==========================================

@app.post("/api/analyze/url")
def url_analysis(request: URLAnalysisRequest):

    result = run_analysis(
        analyze_url,
        request.url,
    )

    return result.to_dict()


@app.post("/api/report/url")
def url_report(request: URLAnalysisRequest):

    result = run_analysis(
        analyze_url,
        request.url,
    )

    return create_pdf(
        generate_url_report,
        result,
        "URL",
    )


# ==========================================
# 02. EMAIL ANALYZER
# ==========================================

@app.post("/api/analyze/email")
async def email_analysis(
    file: UploadFile = File(...),
):
    result = await process_upload(
        file,
        analyze_eml,
        MAX_EMAIL_SIZE,
        (".eml",),
        max_urls=5,
        max_attachments=5,
    )

    return result.to_dict()


@app.post("/api/report/email")
async def email_report(
    file: UploadFile = File(...),
):
    result = await process_upload(
        file,
        analyze_eml,
        MAX_EMAIL_SIZE,
        (".eml",),
        max_urls=5,
        max_attachments=5,
    )

    return await run_in_threadpool(
        create_pdf,
        generate_email_report,
        result,
        "Email",
    )


# ==========================================
# 03. QR CODE ANALYZER
# ==========================================

@app.post("/api/analyze/qr")
async def qr_analysis(
    file: UploadFile = File(...),
):
    result = await process_upload(
        file,
        analyze_qr,
        MAX_QR_SIZE,
        QR_EXTENSIONS,
        max_urls=3,
    )

    return result.to_dict()


@app.post("/api/report/qr")
async def qr_report(
    file: UploadFile = File(...),
):
    result = await process_upload(
        file,
        analyze_qr,
        MAX_QR_SIZE,
        QR_EXTENSIONS,
        max_urls=3,
    )

    return await run_in_threadpool(
        create_pdf,
        generate_qr_report,
        result,
        "QR",
    )


# ==========================================
# 04. FILE ANALYZER
# ==========================================

@app.post("/api/analyze/file")
async def file_analysis(
    file: UploadFile = File(...),
):
    result = await process_upload(
        file,
        analyze_file_bytes,
        MAX_FILE_SIZE,
    )

    return result.to_dict()


@app.post("/api/report/file")
async def file_report(
    file: UploadFile = File(...),
):
    result = await process_upload(
        file,
        analyze_file_bytes,
        MAX_FILE_SIZE,
    )

    return await run_in_threadpool(
        create_pdf,
        generate_file_report,
        result,
        "File",
    )


# ==========================================
# 05. SOCIAL MEDIA ANALYZER
# ==========================================

@app.post("/api/analyze/social")
def social_analysis(
    request: SocialAnalysisRequest,
):
    result = run_analysis(
        analyze_social,
        request.text,
        platform=request.platform,
        max_urls=3,
    )

    return result.to_dict()


@app.post("/api/report/social")
def social_report(
    request: SocialAnalysisRequest,
):
    result = run_analysis(
        analyze_social,
        request.text,
        platform=request.platform,
        max_urls=3,
    )

    return create_pdf(
        generate_social_report,
        result,
        "Social",
    )
