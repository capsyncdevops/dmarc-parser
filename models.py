from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship, Mapped, mapped_column
from db import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    org_name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(255))
    report_id: Mapped[str] = mapped_column(String(255), unique=True)
    date_start: Mapped[DateTime] = mapped_column(DateTime)
    date_end: Mapped[DateTime] = mapped_column(DateTime)
    policy_domain: Mapped[str] = mapped_column(String(255))
    policy_adkim: Mapped[str] = mapped_column(String(10))
    policy_aspf: Mapped[str] = mapped_column(String(10))
    policy_p: Mapped[str] = mapped_column(String(50))
    raw_file_path: Mapped[str] = mapped_column(String(255))

    # records: Mapped[list["Record"]] = relationship(
    #     back_populates="report", cascade="all, delete-orphan"
    # )
    records: Mapped[list["Record"]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )


class Record(Base):
    __tablename__ = "records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"))
    source_ip: Mapped[str] = mapped_column(String(50))
    count: Mapped[int] = mapped_column(Integer)
    disposition: Mapped[int] = mapped_column(String(50))
    dkim_result: Mapped[str] = mapped_column(String(50))
    spf_result: Mapped[str] = mapped_column(String(50))
    header_from: Mapped[str] = mapped_column(String(255))

    # report: Mapped["Report"] = relationship("Report", back_populates="records")
    report: Mapped["Report"] = relationship(back_populates="records")
    # auth_results: Mapped[list["AuthResult"]] = relationship(
    #     back_populates="record", cascade="all, delete-orphan"
    # )
    auth_results: Mapped[list["AuthResult"]] = relationship(
        back_populates="record", cascade="all, delete-orphan"
    )


class AuthResult(Base):
    __tablename__ = "auth_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    record_id: Mapped[int] = mapped_column(ForeignKey("records.id"))
    auth_type: Mapped[str] = mapped_column(String(20))
    domain: Mapped[str] = mapped_column(String(255))
    result: Mapped[str] = mapped_column(String(50))
    selector: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # DKIM only

    # record: Mapped["Record"] = relationship(back_populates="auth_results")
    record: Mapped["Record"] = relationship(back_populates="auth_results")
