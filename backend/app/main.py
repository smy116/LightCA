from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import get_db
from app.services.cert_service import get_certificate_tree

app = FastAPI(
    title="LightCA",
    description="Docker + Python Web CA certificate, key management and issuance platform",
    version="0.1.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Configure Jinja2 templates
jinja_templates = Jinja2Templates(directory="app/templates")


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "data": None,
            "error": {"code": f"HTTP_{exc.status_code}", "detail": exc.detail},
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "message": "Validation error",
            "data": None,
            "error": {"code": "VALIDATION_ERROR", "detail": str(exc)},
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Internal server error",
            "data": None,
            "error": {
                "code": "INTERNAL_ERROR",
                "detail": str(exc) if settings.DEBUG else "An unexpected error occurred",
            },
        },
    )


# Import and register API routers
from app.api import auth, keys, certificates, templates, crl, stats, public

app.include_router(auth.router)
app.include_router(keys.router)
app.include_router(certificates.router)
app.include_router(templates.router)
app.include_router(crl.router)
app.include_router(stats.router)
app.include_router(public.router)


# Frontend routes
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return jinja_templates.TemplateResponse(request, "auth/login.html")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return jinja_templates.TemplateResponse(request, "dashboard.html")


@app.get("/ca", response_class=HTMLResponse)
async def ca_list(request: Request):
    return jinja_templates.TemplateResponse(request, "ca/list.html")


@app.get("/ca/detail", response_class=HTMLResponse)
async def ca_detail(request: Request):
    return jinja_templates.TemplateResponse(request, "ca/detail.html")


@app.get("/ca/tree", response_class=HTMLResponse)
async def ca_tree(request: Request, db=Depends(get_db)):
    tree_data = get_certificate_tree(db)

    def normalize(node):
        node_type = node.get("type")
        node_status = node.get("status")
        return {
            "id": node.get("id"),
            "type": node_type.value if hasattr(node_type, "value") else node_type,
            "subject_cn": node.get("subject_cn"),
            "status": node_status.value if hasattr(node_status, "value") else node_status,
            "children": [normalize(child) for child in node.get("children", [])],
        }

    return jinja_templates.TemplateResponse(
        request,
        "ca/tree.html",
        {"tree_data": [normalize(node) for node in tree_data]},
    )


@app.get("/certificates", response_class=HTMLResponse)
async def certificates_list(request: Request):
    return jinja_templates.TemplateResponse(request, "certificates/list.html")


@app.get("/certificates/sign", response_class=HTMLResponse)
async def certificates_sign(request: Request):
    return jinja_templates.TemplateResponse(request, "certificates/sign.html")


@app.get("/certificates/import", response_class=HTMLResponse)
async def certificates_import(request: Request):
    return jinja_templates.TemplateResponse(request, "certificates/import.html")


@app.get("/certificates/detail", response_class=HTMLResponse)
async def certificates_detail(request: Request):
    return jinja_templates.TemplateResponse(request, "certificates/detail.html")


@app.get("/keys", response_class=HTMLResponse)
async def keys_list(request: Request):
    return jinja_templates.TemplateResponse(request, "keys/list.html")


@app.get("/templates", response_class=HTMLResponse)
async def templates_list(request: Request):
    return jinja_templates.TemplateResponse(request, "templates/list.html")


@app.get("/templates/create", response_class=HTMLResponse)
async def templates_create(request: Request):
    return jinja_templates.TemplateResponse(request, "templates/create.html")


@app.get("/templates/detail", response_class=HTMLResponse)
async def templates_detail(request: Request):
    return jinja_templates.TemplateResponse(request, "templates/detail.html")


@app.get("/crl", response_class=HTMLResponse)
async def crl_list(request: Request):
    return jinja_templates.TemplateResponse(request, "crl/list.html")


@app.get("/crl/revocations", response_class=HTMLResponse)
async def crl_revocations(request: Request):
    return jinja_templates.TemplateResponse(request, "crl/revocations.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
