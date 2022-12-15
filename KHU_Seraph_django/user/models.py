from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
import uuid

class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, name, school_id, type, department, purpose, password,):
        if not email:
            raise ValueError('must have user email')
        if not password:
            raise ValueError('must have user password')

        server_uid = generate_server_uid(type)
        cluster = get_cluster(type, department)

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            school_id=school_id,
            server_uid=server_uid,
            allowed_cluster=cluster,
            type=type,
            department=department,
            purpose=purpose,
            password=password,
        )

        user.set_password(password)
        user.save(using=self._db)
        
        return user
        
    def create_superuser(self, email, name, school_id, password,):
        type="Adminisrator"
        department="Adminisrator"
        purpose="Adminisrator"
        etc="Adminisrator"

        user = self.create_user(
            email=self.normalize_email(email),
            name=name,
            school_id=school_id,
            type=type,
            department=department,
            purpose=purpose,
            password=password,
        )
        user.is_admin = True
        user.is_superuser = True
        user.is_active = True
        user.save(using=self._db)
        
        return user

class User(AbstractBaseUser, PermissionsMixin):
    objects = UserManager()
    
    email = models.EmailField(max_length=255, unique=True, blank=False)
    name = models.CharField(max_length=255, blank=False, null=False)
    school_id = models.CharField(max_length=255, blank=False, null=False, unique=True)
    server_uid = models.IntegerField(default=0, unique=True)
    allowed_cluster = models.CharField(max_length=255, blank=False, null=False)
    type = models.CharField(max_length=255, blank=False, null=False,)
    department = models.CharField(max_length=50, blank=False, null=False,)
    purpose = models.CharField(max_length=255, blank=False, null=False)
    username = models.CharField(max_length=255, blank=False, null=False, default='default')
    created_at = models.DateTimeField('created_at', auto_now_add=True)
    updated_at = models.DateTimeField('updated_at', auto_now=True)

    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'school_id',]
    
    def __str__(self):
        return self.email
        
    @property
    def is_staff(self):
        return self.is_admin

def get_user_number(_type):
    if _type == "Undergraduate":
        return User.objects.filter(type=_type).count()
    elif _type == "Adminisrator":
        return User.objects.filter(type=_type).count()
    elif _type in ["Undergraduate Researcher", "Master", "PhD", "Professor", "Other"]:
        count = 0
        for t in ["Undergraduate Researcher", "Master", "PhD", "Professor", "Other"]:
            count += User.objects.filter(type=t).count()
        return count
    else:
        raise ValueError('invalid type')

def get_start_value(_type):
    if _type == "Adminisrator":
        return 10000
    elif _type == "Undergraduate":
        return 20000
    elif _type in ["Undergraduate Researcher", "Master", "PhD", "Professor", "Other"]:
        return 30000
    else:
        raise ValueError('invalid type')

def generate_server_uid(_type):
    user_number = get_user_number(_type)
    start_value = get_start_value(_type)

    return start_value + user_number

def get_cluster(_department, _type):
    if _type == "Adminisrator":
        return "All"
    elif _type == "Undergraduate" and _department in ["CE", "SWCON"]:
        return "SW"
    elif _type == "Undergraduate" and _department in ["EE", "BE"]:
        return "CE"
    elif _type == "Undergraduate" and _department == "AI":
        return "AI"
    elif _type in ["Undergraduate Researcher", "Master", "PhD", "Professor", "Other"]:
        return "AI"
    else:
        raise ValueError('invalid type and department')