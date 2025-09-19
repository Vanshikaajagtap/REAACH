"""Database Models"""
from datetime import datetime
from enum import Enum
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Boolean, Enum as SQLAlchemyEnum, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Base = declarative_base()


class UserRole(Enum):
    CHW = "chw"  
    SUPERVISOR = "supervisor"
    ADMIN = "admin"


class AlertType(Enum):
    SOS = "sos"
    TREND = "trend"
    MEDICATION = "medication"
    APPOINTMENT = "appointment"


class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SQLAlchemyEnum(UserRole), nullable=False)
    phone_number = Column(String(20))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    
    patients = relationship("Patient", back_populates="assigned_chw")
    reports = relationship("Report", back_populates="chw")
    alerts_created = relationship("Alert", back_populates="created_by", foreign_keys="Alert.created_by_id")
    alerts_assigned = relationship("Alert", back_populates="assigned_to", foreign_keys="Alert.assigned_to_id")
    
    def set_password(self, password):
        self.hashed_password = pwd_context.hash(password)
    
    def verify_password(self, password):
        return pwd_context.verify(password, self.hashed_password)
    
    def __repr__(self):
        return f"<User(id={self.id}, name='{self.first_name} {self.last_name}', role='{self.role.value}')>"

class Patient(Base):
    __tablename__ = 'patients'
    
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    date_of_birth = Column(DateTime, nullable=False)
    gender = Column(String(10), nullable=False)
    phone_number = Column(String(20))
    address = Column(Text)
    emergency_contact_name = Column(String(100))
    emergency_contact_phone = Column(String(20))
    medical_history = Column(Text)
    current_medications = Column(Text)
    allergies = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    assigned_chw_id = Column(Integer, ForeignKey('users.id'), nullable=False)
 
    assigned_chw = relationship("User", back_populates="patients")
    reports = relationship("Report", back_populates="patient")
    alerts = relationship("Alert", back_populates="patient")
    
    def __repr__(self):
        return f"<Patient(id={self.id}, name='{self.first_name} {self.last_name}')>"

class Report(Base):
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True, index=True)
    visit_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    symptoms = Column(Text)
    blood_pressure_systolic = Column(Integer)
    blood_pressure_diastolic = Column(Integer)
    heart_rate = Column(Integer)
    temperature = Column(Float)
    weight = Column(Float)
    height = Column(Float)
    notes = Column(Text)
    recommendations = Column(Text)
    follow_up_required = Column(Boolean, default=False)
    follow_up_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    patient_id = Column(Integer, ForeignKey('patients.id'), nullable=False)
    chw_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    patient = relationship("Patient", back_populates="reports")
    chw = relationship("User", back_populates="reports")
    
    def __repr__(self):
        return f"<Report(id={self.id}, patient_id={self.patient_id}, date={self.visit_date})>"

class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(SQLAlchemyEnum(AlertType), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20))  
    is_resolved = Column(Boolean, default=False)
    resolved_notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    patient_id = Column(Integer, ForeignKey('patients.id'))
    created_by_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    assigned_to_id = Column(Integer, ForeignKey('users.id'))
    
    patient = relationship("Patient", back_populates="alerts")
    created_by = relationship("User", back_populates="alerts_created", foreign_keys=[created_by_id])
    assigned_to = relationship("User", back_populates="alerts_assigned", foreign_keys=[assigned_to_id])
    
    def __repr__(self):
        return f"<Alert(id={self.id}, type='{self.alert_type.value}', severity='{self.severity}')>"

def setup_database(connection_string):
    engine = create_engine(connection_string)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal

if __name__ == "__main__":
    
    SQLALCHEMY_DATABASE_URL = "sqlite:///./healthcare.db"
    SessionLocal = setup_database(SQLALCHEMY_DATABASE_URL)
    
    db = SessionLocal()
    
    try:
        
        admin_user = User(
            first_name="Admin",
            last_name="User",
            email="admin@example.com",
            role=UserRole.ADMIN,
            phone_number="+1234567890"
        )
        admin_user.set_password("adminpassword")
        db.add(admin_user)
        
        supervisor_user = User(
            first_name="Supervisor",
            last_name="User",
            email="supervisor@example.com",
            role=UserRole.SUPERVISOR,
            phone_number="+1234567891"
        )
        supervisor_user.set_password("supervisorpassword")
        db.add(supervisor_user)
        
        chw_user = User(
            first_name="Community",
            last_name="Health Worker",
            email="chw@example.com",
            role=UserRole.CHW,
            phone_number="+1234567892"
        )
        chw_user.set_password("chwpassword")
        db.add(chw_user)
        
        db.commit()
        
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth=datetime(2007, 5, 15),
            gender="Male",
            phone_number="+0987654321",
            address="123 Main St, Anytown, India",
            emergency_contact_name="Jane Doe",
            emergency_contact_phone="+0987654322",
            medical_history="Hypertension, Type 2 Diabetes",
            current_medications="Lisinopril 10mg daily, Metformin 500mg twice daily",
            allergies="Penicillin",
            assigned_chw_id=chw_user.id
        )
        db.add(patient)
        db.commit()
        
        report = Report(
            visit_date=datetime.utcnow(),
            symptoms="Patient reports feeling fatigued and occasional dizziness",
            blood_pressure_systolic=150,
            blood_pressure_diastolic=95,
            heart_rate=78,
            temperature=98.6,
            oxygen_saturation=97.5,
            weight=185.5,
            height=70.0,
            notes="Patient advised to monitor BP twice daily and reduce salt intake",
            recommendations="Follow up in 2 weeks, consider medication adjustment if BP remains elevated",
            follow_up_required=True,
            follow_up_date=datetime.utcnow(),
            patient_id=patient.id,
            chw_id=chw_user.id
        )
        db.add(report)
        db.commit()
        
        alert = Alert(
            alert_type=AlertType.TREND,
            title="Elevated Blood Pressure Trend",
            description="Patient has shown consistently elevated blood pressure readings over the past 3 visits",
            severity="high",
            patient_id=patient.id,
            created_by_id=chw_user.id,
            assigned_to_id=supervisor_user.id
        )
        db.add(alert)
        db.commit()
        
        print("Database populated with sample data!")
        
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()