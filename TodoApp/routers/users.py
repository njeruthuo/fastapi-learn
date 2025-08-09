from typing import Annotated
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import Users

from fastapi import APIRouter, Depends, HTTPException
from starlette import status
from database import SessionLocal

from .auth import authenticate_user, get_current_user, bcrypt_context


router = APIRouter(
    prefix="/users",
    tags=['users']
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=5, max_length=15)


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.get('/info', status_code=status.HTTP_200_OK)
async def get_user_info(db: db_dependency, user: user_dependency):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed!")

    current_user = db.query(Users).filter(
        Users.username == user.get('username')).first()
    return {k: v for k, v in current_user.__dict__.items() if k != 'hashed_password' and not k.startswith('_')}


@router.post('/change-password')
async def change_passwords(db: db_dependency, user: user_dependency, form_data: ChangePasswordRequest):

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed!")

    current_user = db.query(Users).filter(Users.id == user.get('id')).first()

    if not authenticate_user(current_user.username, form_data.old_password, db):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not verify credentials')

    current_user.hashed_password = bcrypt_context.hash(form_data.new_password)
    db.commit()
