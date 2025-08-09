from datetime import timedelta, timezone, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from starlette import status
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from jose import jwt, JWTError

from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

from database import SessionLocal
from models import Users

router = APIRouter(
    prefix="/auth",
    tags=['auth']
)

SECRET_KEY = '3fa83949d71913d5648107a554f79c3765228af3235f381387d2253c2fa40b3e'
ALGORITHM = 'HS256'


class Token(BaseModel):
    access_token: str
    token_type: str = 'bearer'


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oath2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False

    if not bcrypt_context.verify(password, hash=user.hashed_password):
        return False

    return user


def create_access_token(username: str, role: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, 'role': role}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oath2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        user_role: int = payload.get('role')

        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not verify credentials')

        return {'username': username, 'id': user_id, 'user_role': user_role}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not verify credentials')


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=100)
    first_name: str = Field(min_length=1, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=6, max_length=100)
    role: str


@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    user = Users(
        username=create_user_request.username,
        email=create_user_request.email,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        role=create_user_request.role,
        is_active=True
    )

    db.add(user)
    db.commit()
    return user


@router.post('/token', response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not verify credentials')
    token = create_access_token(
        user.get('username'), user.get('role'), user.get('id'), timedelta(minutes=20))

    return {'access_token': token, 'token_type': 'bearer'}
