# models.py - 権限管理機能付きデータベースモデル定義
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class UserRole(Base):
    """ユーザー権限マスタ"""
    __tablename__ = "user_roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)  # 管理者, 営業, マーケ
    description = Column(String(255), default="")
    permissions = Column(Text, default="")  # JSON形式で権限を格納
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    """ログインユーザー管理"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("user_roles.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # リレーション
    role = relationship("UserRole", backref="users")

class SnsMedia(Base):
    """SNS媒体マスタ（Web編集可能）"""
    __tablename__ = "sns_media"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)  # Twitter, Instagram, Facebook等
    icon = Column(String(100), default="")  # アイコンURL
    is_active = Column(Boolean, default=True)
    sort_order = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class CustomerStatus(Base):
    """顧客ステータスマスタ（Web編集可能）"""
    __tablename__ = "customer_status"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)  # 見込み客, 契約済み, 失注等
    color_code = Column(String(7), default="#000000")  # 表示色
    description = Column(String(255), default="")  # 説明
    is_active = Column(Boolean, default=True)
    sort_order = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Customer(Base):
    """顧客情報メインテーブル"""
    __tablename__ = "customers"
    
    id = Column(Integer, primary_key=True, index=True)
    sns_media_id = Column(Integer, ForeignKey("sns_media.id"), nullable=False)
    sns_id = Column(String(100), nullable=False, index=True)  # SNS上のID
    real_name = Column(String(100), nullable=False, index=True)  # 本名
    status_id = Column(Integer, ForeignKey("customer_status.id"), nullable=False)
    registration_date = Column(DateTime, default=datetime.utcnow)  # 登録日
    notes = Column(Text, default="")  # メモ欄
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # 登録者
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # 更新者
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # リレーション
    sns_media = relationship("SnsMedia", backref="customers")
    status = relationship("CustomerStatus", backref="customers")
    appointments = relationship("Appointment", back_populates="customer", cascade="all, delete-orphan")
    creator = relationship("User", foreign_keys=[created_by], backref="created_customers")
    updater = relationship("User", foreign_keys=[updated_by], backref="updated_customers")

class Appointment(Base):
    """アポイントメント履歴（最大20件）"""
    __tablename__ = "appointments"
    
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    appointment_date = Column(DateTime, nullable=False)  # アポ実施日
    staff_name = Column(String(100), nullable=False)  # 実施者名
    status = Column(String(50), nullable=False)  # アポステータス（成約、見送り等）
    result_content = Column(Text, nullable=False)  # 結果内容（自由記入）
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # 登録者
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # リレーション
    customer = relationship("Customer", back_populates="appointments")
    creator = relationship("User", backref="created_appointments")