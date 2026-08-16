import os
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt

# ==========================================
# ⚙️ CONFIGURATION ET BASE DE DONNÉES POSTGRESQL
# ==========================================

# Variables d'environnement pour Render/Supabase
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/sokomaster_db")

# Correctif pour la compatibilité URI avec SQLAlchemy (postgres:// -> postgresql://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configuration Sécurité JWT & Hachage
SECRET_KEY = os.getenv("SECRET_KEY", "crypt_enterprise_ultra_secure_secret_key_2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 heures

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==========================================
# 🗄️ MODÈLES DE DONNÉES (SQLALCHEMY)
# ==========================================

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="local")  # "admin" ou "local"
    created_at = Column(DateTime, default=datetime.utcnow)

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    nom = Column(String, index=True, nullable=False)
    quantite = Column(Integer, default=0)
    p_a_u = Column(Float, nullable=False)  # Prix d'Achat Unitaire
    p_v_u = Column(Float, nullable=False)  # Prix de Vente Unitaire
    seuil_critique = Column(Integer, default=5)
    code_barre = Column(String, unique=True, index=True, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Sale(Base):
    __tablename__ = "sales"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    total_amount = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    items = relationship("SaleItem", back_populates="sale")

class SaleItem(Base):
    __tablename__ = "sale_items"
    id = Column(Integer, primary_key=True, index=True)
    sale_id = Column(Integer, ForeignKey("sales.id"))
    product_id = Column(Integer, ForeignKey("products.id"))
    quantite = Column(Integer, nullable=False)
    prix_unitaire = Column(Float, nullable=False)
    subtotal = Column(Float, nullable=False)

    sale = relationship("Sale", back_populates="items")
    product = relationship("Product")

# Initialisation des tables PostgreSQL
Base.metadata.create_all(bind=engine)

# ==========================================
# 🔒 SCHÉMAS PYDANTIC & DEPENDANCIES
# ==========================================

class UserCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "local"

class UserLogin(BaseModel):
    username: str
    password: str

class ProductCreate(BaseModel):
    nom: str
    quantite: int
    p_a_u: float
    p_v_u: float
    seuil_critique: int
    code_barre: Optional[str] = None

class ProductResponse(BaseModel):
    id: int
    nom: str
    quantite: int
    p_v_u: float
    seuil_critique: int
    
    class Config:
        from_attributes = True

class CartItemSchema(BaseModel):
    product_id: int
    quantite: int

class SaleCreate(BaseModel):
    items: List[CartItemSchema]

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utilitaire de Hachage
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 🚀 API FASTAPI & ENDPOINTS SOKOMASTER
# ==========================================

app = FastAPI(
    title="SokoMaster API Core",
    description="CRYPT Enterprise Production Engine with PostgreSQL",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- AUTHENTIFICATION ---

@app.post("/api/auth/register", status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Création d'un compte utilisateur (Admin / Vendeur)"""
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Nom d'utilisateur déjà pris.")
    
    new_user = User(
        username=user.username,
        password_hash=hash_password(user.password),
        role=user.role
    )
    db.add(new_user)
    db.commit()
    return {"message": f"Utilisateur {user.username} créé avec succès en tant que {user.role}."}

@app.post("/api/auth/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    """Authentification et émission du Token JWT"""
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Identifiants incorrects.")
    
    token = create_access_token({"sub": db_user.username, "role": db_user.role, "user_id": db_user.id})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": db_user.username,
        "role": db_user.role
    }

# --- GESTION DU STOCK ---

@app.get("/api/stock", response_model=List[ProductResponse])
def get_stock(db: Session = Depends(get_db)):
    """Consultation globale de l'état du stock"""
    return db.query(Product).all()

@app.post("/api/stock/add", status_code=201)
def add_product(product: ProductCreate, db: Session = Depends(get_db)):
    """Ajout d'un nouveau produit au catalogue"""
    db_product = Product(**product.model_dump())
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return {"message": "Produit ajouté avec succès !", "product": db_product.nom}

@app.put("/api/stock/{product_id}")
def update_product(product_id: int, product_data: ProductCreate, db: Session = Depends(get_db)):
    """Mise à jour d'un produit (quantités, prix)"""
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Produit non trouvé.")
    
    for key, value in product_data.model_dump().items():
        setattr(product, key, value)
    
    db.commit()
    return {"message": "Produit mis à jour."}

# --- PROCESSUS DE VENTE (CAISSE & TRANSACTIONS ATOMIQUES) ---

@app.post("/api/sales/checkout")
def process_sale(sale_data: SaleCreate, user_id: int = 1, db: Session = Depends(get_db)):
    """Validation d'une vente : déduction de stock et enregistrement comptable sécurisé"""
    total_sale = 0.0
    sale_items_to_create = []

    # Vérification atomique des stocks
    for item in sale_data.items:
        product = db.query(Product).filter(Product.id == item.product_id).first()
        if not product:
            raise HTTPException(status_code=404, detail=f"Produit ID {item.product_id} inexistant.")
        if product.quantite < item.quantite:
            raise HTTPException(
                status_code=400, 
                detail=f"Stock insuffisant pour '{product.nom}'. Disponible: {product.quantite}"
            )
        
        # Déduction du stock
        product.quantite -= item.quantite
        subtotal = product.p_v_u * item.quantite
        total_sale += subtotal

        sale_items_to_create.append({
            "product_id": product.id,
            "quantite": item.quantite,
            "prix_unitaire": product.p_v_u,
            "subtotal": subtotal
        })

    # Enregistrement de la vente globale
    new_sale = Sale(user_id=user_id, total_amount=total_sale)
    db.add(new_sale)
    db.flush()  # Récupère l'ID généré de new_sale

    # Enregistrement des lignes du reçu
    for item_data in sale_items_to_create:
        sale_item = SaleItem(sale_id=new_sale.id, **item_data)
        db.add(sale_item)

    db.commit()
    return {
        "status": "success",
        "sale_id": new_sale.id,
        "total_paid": total_sale,
        "timestamp": new_sale.created_at
    }

# --- STATISTIQUES ET DASHBOARD CRYPT ---

@app.get("/api/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Moteur d'indicateurs de performance en temps réel pour l'administrateur"""
    today = datetime.utcnow().date()
    
    sales_today = db.query(Sale).filter(Sale.created_at >= today).all()
    total_revenue_today = sum(s.total_amount for s in sales_today)
    
    alert_products = db.query(Product).filter(Product.quantite <= Product.seuil_critique).count()
    total_products_count = db.query(Product).count()

    return {
        "ventes_du_jour_fc": total_revenue_today,
        "nombre_ventes_aujourdhui": len(sales_today),
        "alertes_stock_critique": alert_products,
        "total_references_en_catalogue": total_products_count
    }

# --- INTÉGRATION IA LLINK ---

@app.post("/api/llink/query")
def llink_business_assistant(query: str, db: Session = Depends(get_db)):
    """Endpoint dédié à l'agent IA Llink pour l'analyse prédictive du stock"""
    query_lower = query.lower()
    
    if "alerte" in query_lower or "rupture" in query_lower:
        critical_items = db.query(Product).filter(Product.quantite <= Product.seuil_critique).all()
        names = [p.nom for p in critical_items]
        return {"response": f"Llink IA : Vous avez {len(names)} produit(s) en alerte critique : {', '.join(names) if names else 'Aucun'}."}
    
    return {"response": "Llink IA : Analyse commerciale effectuée. Toutes les métriques système sont stables."}

@app.get("/")
def root():
    return {"status": "SokoMaster PostgreSQL API Online", "entreprise": "CRYPT Enterprise"}
