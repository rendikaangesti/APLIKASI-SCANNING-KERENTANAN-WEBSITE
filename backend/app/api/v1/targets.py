from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from urllib.parse import urlparse
import secrets
import socket
import httpx
from typing import List

from app.core.database import get_db
from app.models.scan import Target
from app.schemas.scan import TargetCreate, TargetResponse
from app.core.ssrf_guard import validate_and_sanitize_target

router = APIRouter()

@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)):
    is_valid, normalized_url, err_msg = validate_and_sanitize_target(payload.url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    parsed = urlparse(normalized_url)
    domain = parsed.hostname

    # Check if target already exists
    res = await db.execute(select(Target).where(Target.url == normalized_url))
    existing = res.scalar_one_or_none()
    if existing:
        return existing

    token = f"vh-verify-{secrets.token_hex(16)}"
    new_target = Target(
        url=normalized_url,
        domain=domain,
        is_verified=False,
        verification_token=token
    )
    db.add(new_target)
    await db.commit()
    await db.refresh(new_target)
    return new_target

@router.get("/", response_model=List[TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return res.scalars().all()

@router.post("/{target_id}/verify", response_model=TargetResponse)
async def verify_target_ownership(target_id: int, method: str = "http", db: AsyncSession = Depends(get_db)):
    """
    Verifikasi kepemilikan domain target secara etis melalui HTTP file atau DNS TXT.
    """
    res = await db.execute(select(Target).where(Target.id == target_id))
    target = res.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target tidak ditemukan.")

    if target.is_verified:
        return target

    if method == "http":
        verify_url = f"{target.url}/.well-known/vulnhunter-challenge.txt"
        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            try:
                r = await client.get(verify_url)
                if r.status_code == 200 and target.verification_token in r.text:
                    target.is_verified = True
                    await db.commit()
                    await db.refresh(target)
                    return target
                else:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Token verifikasi tidak ditemukan pada {verify_url}. Pastikan file berisi token: {target.verification_token}"
                    )
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Gagal memeriksa HTTP file: {str(e)}")
    else:
        # DNS TXT verification
        import asyncio
        txt_record_host = f"_vulnhunter-challenge.{target.domain}"
        token_found = False

        # 1. Query DNS-over-HTTPS (Cloudflare DoH)
        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            try:
                doh_res = await client.get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": txt_record_host, "type": "TXT"},
                    headers={"Accept": "application/dns-json"}
                )
                if doh_res.status_code == 200:
                    data = doh_res.json()
                    answers = data.get("Answer", [])
                    for ans in answers:
                        txt_val = ans.get("data", "").replace('"', '').strip()
                        if target.verification_token in txt_val:
                            token_found = True
                            break
            except Exception:
                pass

        # 2. Fallback to local nslookup
        if not token_found:
            import subprocess
            loop = asyncio.get_event_loop()
            def query_nslookup():
                try:
                    return subprocess.check_output(
                        ["nslookup", "-type=TXT", txt_record_host],
                        timeout=5,
                        stderr=subprocess.DEVNULL
                    ).decode("latin-1", errors="ignore")
                except Exception:
                    return ""
            raw_out = await loop.run_in_executor(None, query_nslookup)
            if target.verification_token in raw_out:
                token_found = True

        if token_found:
            target.is_verified = True
            await db.commit()
            await db.refresh(target)
            return target
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Verifikasi DNS gagal: TXT record pada host '{txt_record_host}' tidak memuat "
                    f"token verifikasi '{target.verification_token}'. "
                    f"Pastikan TXT record sudah dipublikasikan di DNS provider domain Anda."
                )
            )

