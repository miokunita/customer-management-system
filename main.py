# main.py - FastAPIメインアプリケーション（管理機能付き）
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, or_, text
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
import os
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv

# 環境変数読み込み
load_dotenv()

# モデルをインポート
from models import Base, User, Customer, Appointment, SnsMedia, CustomerStatus, UserRole, Business

# データベース設定
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@localhost/customer_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# セキュリティ設定
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8時間

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="顧客管理システム", version="1.0.0")

# CORS設定（Renderでのデプロイ用）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 本番環境では具体的なURLを指定
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 静的ファイル配信（フロントエンド用）
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Pydanticモデル（APIスキーマ）
class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class CustomerSearch(BaseModel):
    id: int
    sns_id: str
    real_name: str
    sns_media_name: str
    status_name: str
    registration_date: datetime

class CustomerDetail(BaseModel):
    id: int
    sns_id: str
    real_name: str
    sns_media_id: int
    sns_media_name: str
    status_id: int
    status_name: str
    registration_date: datetime
    notes: str
    appointments: List[dict]

class CustomerCreate(BaseModel):
    sns_media_id: int
    sns_id: str
    real_name: str
    status_id: int
    notes: str = ""

class AppointmentCreate(BaseModel):
    appointment_date: Optional[datetime]
    staff_name: str
    status: str
    result_content: str

# 管理機能用のPydanticモデル
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role_id: int
    business_id: Optional[int] = None

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    role_id: Optional[int] = None
    business_id: Optional[int] = None
    is_active: Optional[bool] = None

class BusinessCreate(BaseModel):
    name: str
    description: str = ""
    is_active: bool = True
    sort_order: int = 0

class SnsMediaCreate(BaseModel):
    name: str
    icon: str = ""
    is_active: bool = True
    sort_order: int = 0

class CustomerStatusCreate(BaseModel):
    name: str
    color_code: str = "#000000"
    description: str = ""
    is_active: bool = True
    sort_order: int = 0

# データベースセッション取得
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# パスワードハッシュ化関連
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 現在のユーザー取得
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# 権限チェック用関数
def admin_required(current_user: User = Depends(get_current_user)):
    if current_user.role.name != "管理者":
        raise HTTPException(status_code=403, detail="管理者権限が必要です")
    return current_user

# API エンドポイント

@app.get("/", response_class=HTMLResponse)
async def root():
    if os.path.exists("templates/index.html"):
        with open("templates/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    else:
        return HTMLResponse(content="<h1>顧客管理システム API</h1>")

@app.post("/api/login", response_model=Token)
async def login(user_login: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, user_login.username, user_login.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー名またはパスワードが間違っています",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 最後のログイン時刻を更新
    user.last_login = datetime.utcnow()
    db.commit()
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """現在のユーザー情報取得"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role_name": current_user.role.name,
        "business_name": current_user.business.name if current_user.business else None,
        "permissions": current_user.role.permissions
    }

@app.get("/api/search")
async def search_customers(
    q: str = "",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """顧客検索API - 全項目対象"""
    query = db.query(Customer).join(SnsMedia).join(CustomerStatus)
    
    if q:
        # 簡易検索（LIKE検索）
        search_filter = or_(
            Customer.sns_id.ilike(f"%{q}%"),
            Customer.real_name.ilike(f"%{q}%"),
            Customer.notes.ilike(f"%{q}%")
        )
        customers = query.filter(search_filter).order_by(Customer.created_at.desc()).limit(50).all()
    else:
        # 検索条件なしの場合は最新50件
        customers = query.order_by(Customer.created_at.desc()).limit(50).all()
    
    return [
        CustomerSearch(
            id=c.id,
            sns_id=c.sns_id,
            real_name=c.real_name,
            sns_media_name=c.sns_media.name,
            status_name=c.status.name,
            registration_date=c.registration_date
        ) for c in customers
    ]

@app.get("/api/customer/{customer_id}")
async def get_customer_detail(
    customer_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """顧客詳細取得"""
    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="顧客が見つかりません")
    
    appointments = db.query(Appointment).filter(
        Appointment.customer_id == customer_id
    ).order_by(Appointment.appointment_date.desc()).limit(20).all()
    
    # 履歴に作成者の事業情報を含める
    appointments_data = []
    for apt in appointments:
        creator = db.query(User).filter(User.id == apt.created_by).first()
        appointments_data.append({
            "id": apt.id,
            "appointment_date": apt.appointment_date.isoformat() if apt.appointment_date else None,
            "staff_name": apt.staff_name,
            "status": apt.status,
            "result_content": apt.result_content,
            "created_by_id": apt.created_by,
            "business_name": creator.business.name if creator and creator.business else None
        })
    
    return CustomerDetail(
        id=customer.id,
        sns_id=customer.sns_id,
        real_name=customer.real_name,
        sns_media_id=customer.sns_media_id,
        sns_media_name=customer.sns_media.name,
        status_id=customer.status_id,
        status_name=customer.status.name,
        registration_date=customer.registration_date,
        notes=customer.notes,
        appointments=appointments_data
    )

@app.post("/api/customer")
async def create_customer(
    customer_data: CustomerCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """新規顧客登録"""
    customer = Customer(
        **customer_data.dict(),
        created_by=current_user.id,
        updated_by=current_user.id
    )
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return {"id": customer.id, "message": "顧客を登録しました"}

@app.post("/api/customer/{customer_id}/appointment")
async def add_appointment(
    customer_id: int,
    appointment_data: AppointmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """履歴追加"""
    # 20件制限チェック
    appointment_count = db.query(Appointment).filter(
        Appointment.customer_id == customer_id
    ).count()
    
    if appointment_count >= 20:
        # 最古のアポを削除
        oldest = db.query(Appointment).filter(
            Appointment.customer_id == customer_id
        ).order_by(Appointment.appointment_date.asc()).first()
        db.delete(oldest)
    
    # appointment_dateがNoneの場合は現在時刻を設定
    if appointment_data.appointment_date is None:
        appointment_data.appointment_date = datetime.utcnow()
    
    appointment = Appointment(
        customer_id=customer_id,
        created_by=current_user.id,
        **appointment_data.dict()
    )
    db.add(appointment)
    db.commit()
    return {"message": "履歴を追加しました"}

@app.delete("/api/appointment/{appointment_id}")
async def delete_appointment(
    appointment_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """履歴削除（作成者本人のみ）"""
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not appointment:
        raise HTTPException(status_code=404, detail="履歴が見つかりません")
    
    if appointment.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="この履歴を削除する権限がありません")
    
    db.delete(appointment)
    db.commit()
    return {"message": "履歴を削除しました"}

@app.get("/api/sns-media")
async def get_sns_media(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """SNS媒体一覧取得"""
    media = db.query(SnsMedia).filter(SnsMedia.is_active == True).order_by(SnsMedia.sort_order).all()
    return [{"id": m.id, "name": m.name} for m in media]

@app.get("/api/customer-status")
async def get_customer_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """顧客ステータス一覧取得"""
    statuses = db.query(CustomerStatus).filter(CustomerStatus.is_active == True).order_by(CustomerStatus.sort_order).all()
    return [{"id": s.id, "name": s.name, "color_code": s.color_code} for s in statuses]

@app.get("/api/business")
async def get_business(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """事業一覧取得"""
    businesses = db.query(Business).filter(Business.is_active == True).order_by(Business.sort_order).all()
    return [{"id": b.id, "name": b.name} for b in businesses]

# ============= 管理機能API =============

# ユーザー管理API
@app.get("/api/admin/users")
async def get_users(
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """ユーザー一覧取得（管理者のみ）"""
    users = db.query(User).join(UserRole).all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role_name": user.role.name,
            "role_id": user.role_id,
            "business_name": user.business.name if user.business else None,
            "business_id": user.business_id,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None
        } for user in users
    ]

@app.post("/api/admin/users")
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """新規ユーザー作成（管理者のみ）"""
    # 重複チェック
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="ユーザー名が既に存在します")
    
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="メールアドレスが既に存在します")
    
    # ユーザー作成
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password),
        role_id=user_data.role_id,
        business_id=user_data.business_id
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {"id": user.id, "message": "ユーザーを作成しました"}

@app.put("/api/admin/users/{user_id}")
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """ユーザー情報更新（管理者のみ）"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
    
    # 更新
    for field, value in user_data.dict(exclude_unset=True).items():
        if field == "password" and value:
            setattr(user, "hashed_password", get_password_hash(value))
        elif field != "password":
            setattr(user, field, value)
    
    db.commit()
    return {"message": "ユーザー情報を更新しました"}

@app.delete("/api/admin/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """ユーザー削除（管理者のみ）"""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="自分自身は削除できません")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
    
    db.delete(user)
    db.commit()
    return {"message": "ユーザーを削除しました"}

# 権限管理API
@app.get("/api/admin/roles")
async def get_roles(
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """権限一覧取得"""
    roles = db.query(UserRole).all()
    return [{"id": role.id, "name": role.name, "description": role.description} for role in roles]

# 事業管理API
@app.get("/api/admin/business")
async def get_business_admin(
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """事業管理一覧"""
    businesses = db.query(Business).order_by(Business.sort_order).all()
    return [
        {
            "id": b.id,
            "name": b.name,
            "description": b.description,
            "is_active": b.is_active,
            "sort_order": b.sort_order,
            "created_at": b.created_at.isoformat(),
            "updated_at": b.updated_at.isoformat()
        } for b in businesses
    ]

@app.post("/api/admin/business")
async def create_business(
    business_data: BusinessCreate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """事業作成"""
    business = Business(**business_data.dict())
    db.add(business)
    db.commit()
    db.refresh(business)
    return {"id": business.id, "message": "事業を作成しました"}

@app.put("/api/admin/business/{business_id}")
async def update_business(
    business_id: int,
    business_data: BusinessCreate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """事業更新"""
    business = db.query(Business).filter(Business.id == business_id).first()
    if not business:
        raise HTTPException(status_code=404, detail="事業が見つかりません")
    
    for field, value in business_data.dict().items():
        setattr(business, field, value)
    
    db.commit()
    return {"message": "事業を更新しました"}

@app.delete("/api/admin/business/{business_id}")
async def delete_business(
    business_id: int,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """事業削除"""
    business = db.query(Business).filter(Business.id == business_id).first()
    if not business:
        raise HTTPException(status_code=404, detail="事業が見つかりません")
    
    # 使用中チェック
    user_count = db.query(User).filter(User.business_id == business_id).count()
    if user_count > 0:
        raise HTTPException(status_code=400, detail=f"この事業は{user_count}人のユーザーで使用されているため削除できません")
    
    db.delete(business)
    db.commit()
    return {"message": "事業を削除しました"}

# SNS媒体管理API
@app.get("/api/admin/sns-media")
async def get_sns_media_admin(
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """SNS媒体管理一覧"""
    media = db.query(SnsMedia).order_by(SnsMedia.sort_order).all()
    return [
        {
            "id": m.id,
            "name": m.name,
            "icon": m.icon,
            "is_active": m.is_active,
            "sort_order": m.sort_order,
            "created_at": m.created_at.isoformat(),
            "updated_at": m.updated_at.isoformat()
        } for m in media
    ]

@app.post("/api/admin/sns-media")
async def create_sns_media(
    media_data: SnsMediaCreate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """SNS媒体作成"""
    media = SnsMedia(**media_data.dict())
    db.add(media)
    db.commit()
    db.refresh(media)
    return {"id": media.id, "message": "SNS媒体を作成しました"}

@app.put("/api/admin/sns-media/{media_id}")
async def update_sns_media(
    media_id: int,
    media_data: SnsMediaCreate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """SNS媒体更新"""
    media = db.query(SnsMedia).filter(SnsMedia.id == media_id).first()
    if not media:
        raise HTTPException(status_code=404, detail="SNS媒体が見つかりません")
    
    for field, value in media_data.dict().items():
        setattr(media, field, value)
    
    db.commit()
    return {"message": "SNS媒体を更新しました"}

@app.delete("/api/admin/sns-media/{media_id}")
async def delete_sns_media(
    media_id: int,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """SNS媒体削除"""
    media = db.query(SnsMedia).filter(SnsMedia.id == media_id).first()
    if not media:
        raise HTTPException(status_code=404, detail="SNS媒体が見つかりません")
    
    # 使用中チェック
    customer_count = db.query(Customer).filter(Customer.sns_media_id == media_id).count()
    if customer_count > 0:
        raise HTTPException(status_code=400, detail=f"この媒体は{customer_count}件の顧客で使用されているため削除できません")
    
    db.delete(media)
    db.commit()
    return {"message": "SNS媒体を削除しました"}

# 顧客ステータス管理API
@app.get("/api/admin/customer-status")
async def get_customer_status_admin(
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """顧客ステータス管理一覧"""
    statuses = db.query(CustomerStatus).order_by(CustomerStatus.sort_order).all()
    return [
        {
            "id": s.id,
            "name": s.name,
            "color_code": s.color_code,
            "description": s.description,
            "is_active": s.is_active,
            "sort_order": s.sort_order,
            "created_at": s.created_at.isoformat(),
            "updated_at": s.updated_at.isoformat()
        } for s in statuses
    ]

@app.post("/api/admin/customer-status")
async def create_customer_status(
    status_data: CustomerStatusCreate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """顧客ステータス作成"""
    status = CustomerStatus(**status_data.dict())
    db.add(status)
    db.commit()
    db.refresh(status)
    return {"id": status.id, "message": "顧客ステータスを作成しました"}

@app.put("/api/admin/customer-status/{status_id}")
async def update_customer_status(
    status_id: int,
    status_data: CustomerStatusCreate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """顧客ステータス更新"""
    status = db.query(CustomerStatus).filter(CustomerStatus.id == status_id).first()
    if not status:
        raise HTTPException(status_code=404, detail="顧客ステータスが見つかりません")
    
    for field, value in status_data.dict().items():
        setattr(status, field, value)
    
    db.commit()
    return {"message": "顧客ステータスを更新しました"}

@app.delete("/api/admin/customer-status/{status_id}")
async def delete_customer_status(
    status_id: int,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """顧客ステータス削除"""
    status = db.query(CustomerStatus).filter(CustomerStatus.id == status_id).first()
    if not status:
        raise HTTPException(status_code=404, detail="顧客ステータスが見つかりません")
    
    # 使用中チェック
    customer_count = db.query(Customer).filter(Customer.status_id == status_id).count()
    if customer_count > 0:
        raise HTTPException(status_code=400, detail=f"このステータスは{customer_count}件の顧客で使用されているため削除できません")
    
    db.delete(status)
    db.commit()
    return {"message": "顧客ステータスを削除しました"}

# 初期データ作成（初回起動時）
@app.on_event("startup")
async def create_initial_data():
    db = SessionLocal()
    try:
        # 権限マスタ作成
        if not db.query(UserRole).first():
            roles = [
                UserRole(name="管理者", description="全機能利用可能", permissions='["admin", "sales", "marketing"]'),
                UserRole(name="営業", description="顧客管理・アポ管理", permissions='["sales"]'),
                UserRole(name="マーケ", description="顧客管理・分析機能", permissions='["marketing"]')
            ]
            for role in roles:
                db.add(role)
            db.commit()
        
        # 管理者権限のIDを取得
        admin_role = db.query(UserRole).filter(UserRole.name == "管理者").first()
        
        # デフォルト事業作成
        if not db.query(Business).first():
            businesses = [
                Business(name="営業部", description="営業チーム", sort_order=0),
                Business(name="マーケティング部", description="マーケティングチーム", sort_order=1)
            ]
            for business in businesses:
                db.add(business)
            db.commit()
        
        # デフォルトの事業IDを取得
        default_business = db.query(Business).first()
        
        # デフォルトユーザー作成（管理者権限）
        if not db.query(User).first():
            default_user = User(
                username="admin",
                email="admin@company.com",
                full_name="システム管理者",
                hashed_password=get_password_hash("admin123"),
                role_id=admin_role.id,
                business_id=default_business.id if default_business else None
            )
            db.add(default_user)
        
        # デフォルトSNS媒体
        if not db.query(SnsMedia).first():
            sns_media_list = [
                ("Twitter", "🐦", 0),
                ("Instagram", "📷", 1), 
                ("Facebook", "📘", 2),
                ("TikTok", "🎵", 3),
                ("LinkedIn", "💼", 4),
                ("YouTube", "📺", 5)
            ]
            for name, icon, order in sns_media_list:
                media = SnsMedia(name=name, icon=icon, sort_order=order)
                db.add(media)
        
        # デフォルト顧客ステータス
        if not db.query(CustomerStatus).first():
            status_list = [
                ("見込み客", "#fbbf24", "初期接触段階", 0),
                ("接触中", "#3b82f6", "積極的にアプローチ中", 1),
                ("商談中", "#8b5cf6", "具体的な提案段階", 2),
                ("契約済み", "#10b981", "成約完了", 3),
                ("失注", "#ef4444", "今回は見送り", 4),
                ("保留", "#6b7280", "一時的に保留中", 5)
            ]
            for name, color, desc, order in status_list:
                status = CustomerStatus(
                    name=name, 
                    color_code=color, 
                    description=desc, 
                    sort_order=order
                )
                db.add(status)
        
        db.commit()
        print("初期データ作成完了")
    except Exception as e:
        print(f"初期データ作成エラー: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)