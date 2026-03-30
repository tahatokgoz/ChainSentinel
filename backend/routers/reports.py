from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Report, Scan
from backend.schemas import ReportOut
from backend.services.report_generator import generate_report

router = APIRouter()


@router.post("/reports/generate/{scan_id}", response_model=ReportOut)
def create_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan is not completed yet")

    filepath = generate_report(scan_id, db)
    report = Report(scan_id=scan_id, file_path=filepath)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/reports/{scan_id}")
def download_report(scan_id: int, db: Session = Depends(get_db)):
    report = (
        db.query(Report)
        .filter(Report.scan_id == scan_id)
        .order_by(Report.created_at.desc())
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail="Report not found. Generate one first.")

    filename = report.file_path.split("/")[-1].split("\\")[-1]
    return FileResponse(
        report.file_path,
        media_type="application/pdf",
        filename=filename,
    )
