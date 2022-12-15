from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login # login함수와 이름이 겹쳐서
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import update_session_auth_hash, get_user_model
from django.contrib.auth.forms import PasswordChangeForm
from user.admin import UserCreationForm, UserChangeForm
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMessage
from .token import account_activation_token
from django.utils.encoding import force_bytes, force_str
from django.http import HttpResponse, HttpResponseRedirect
from user.models import User
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.edit import FormView
from django.db.models import Max

from accounts.forms import CustomSetPasswordForm
from global_vars import *


def profile(request):
    context = {
        'id' : request.user.username,
        'cluster' : request.user.allowed_cluster,
        'clsuter_masterip': get_cluster_ip(request.user.allowed_cluster)
    }
    return render(request, 'accounts/profile.html', context)


def get_cluster_ip(cluster):
    get_domain_with_name = lambda name: f'{name}.khu.ac.kr({IPS[CLUSTER_NAMES.index(name)]})'
    if cluster == CLUSTER_ALL:
        return ','.join(map(get_domain_with_name, CLUSTER_NAMES))
    elif cluster not in CLUSTER_NAMES:
        error_message = f'invalid cluster name, given {cluster} which is not in the cluster set: {str(CLUSTER_NAMES)}'
        raise ValueError(error_message)
    else:
        return get_domain_with_name(cluster)


def login(request):
    if request.method=='POST':
        # data는 forms.form 두번쨰 인자이므로 data = 은 생략 가능
        form = AuthenticationForm(request, data=request.POST) # 먼저 request 인자를 받아야함
        if form.is_valid():
            # 세션 CREATE/ form.get_user는 User 객체 반환
            auth_login(request, form.get_user())
            return redirect('accounts:profile') # 로그인 성공시 메인페이지 이동
    else:
        form = AuthenticationForm()

    context = {
        'form' : form,
    }
    return render(request, 'accounts/main.html', context)


def logout(request):
    if not request.user.is_authenticated:
        return redirect('accounts:signup')

    auth_logout(request)

    return redirect('accounts:login')


def signup(request):
    if request.method== "POST":
        form = UserCreationForm(request.POST)
        user_db = User.objects.all()
        if user_db.filter(email=request.POST['email']).exists():
            messages.error(request, 'This email already exists.')
            return redirect('accounts:signup')

        if user_db.filter(school_id=request.POST['school_id']).exists():
            messages.error(request, 'This student id already exists.')
            return redirect('accounts:signup')

        if form.is_valid():
            email = form.cleaned_data.get('email')
            user = form.save(commit=False)
            user.is_active = False
            user.allowed_cluster = get_cluster(user.department, user.type)
            num_not_active = User.objects.filter(is_active=False).count()
            user.server_uid = num_not_active + 1000000 # invalid uid
            user.save()
            current_site = get_current_site(request)
            mail_subject = '[KHU Seraph Signup Verification]'
            message = render_to_string('accounts/signup_email.html', {
                            'user': user,
                            'domain': current_site.domain,
                            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                            'token': account_activation_token.make_token(user),
                        })
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.send()
            messages.info(request, 'Please check your email to complete your signup.')
            return redirect('accounts:signup')

    else: # 회원가입 페이지 첫 접근
        form = UserCreationForm()
    context = {
        'form' : form,
    }
    return render(request, 'accounts/signup.html', context)

def activate(request, uidb64, token):
    # superuser는 해당 없음
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        username = user.email.split('@')[0]
        if username[0].isdigit():
            username = 'a' + username
        user.username = username
        server_uid = generate_server_uid(user.type)
        user.server_uid = server_uid
        user.save()
        return redirect('accounts:login')
    else:
        return HttpResponse('Activation link is invalid!')

def generate_server_uid(_type):
    if _type == "Adminisrator":
        start_value = 10000
    elif _type in ["Undergraduate Researcher", "Undergraduate", "Competition"]:
        start_value = 20000
    elif _type in ["Master", "PhD", "Professor", "Other"]:
        start_value = 30000
    else:
        raise ValueError('invalid type')

    users = User.objects.filter(server_uid__gte=start_value, server_uid__lt=start_value+10000)

    if users.count() == 0:
        return start_value
    else:
        max_uid = users.aggregate(Max('server_uid'))['server_uid__max']
        return max_uid + 1

def get_cluster(_department, _type):
    if _type == "Adminisrator":
        return CLUSTER_ALL
    elif _type in ["Undergraduate Researcher", "Undergraduate"] and _department in [DEPART_SWCON]:
        return CLUSTER_AURORA
    elif _type == "Competition":
        return CLUSTER_MOANA
    elif _type in ["Undergraduate Researcher", "Undergraduate"] and _department in [DEPART_EE, DEPART_BME, DEPART_CE]:
        return CLUSTER_MOANA
    elif _type in ["Undergraduate Researcher", "Undergraduate"] and _department in [DEPART_AI]:
        return CLUSTER_ARIEL
    elif _type in ["Master", "PhD", "Professor", "Other"]:
        return CLUSTER_ARIEL
    else:
        raise ValueError('invalid type and department')

def delete(request):
    if request.user.name == 'sadmin':
        return HttpResponse(status=500)

    if request.user.is_authenticated:
        request.user.delete()
        auth_logout(request) # 세션 지워주기

    return redirect('accounts:login')

@login_required
def update(request):
    if request.method == "POST":
        form = UserChangeForm(request.POST, instance=request.user)
        if form.is_valid():
            user = form.save()
            user.allowed_cluster = get_cluster(request.POST['department'], request.POST['type'])
            user.save()
            update_session_auth_hash(request, user) # session 을 update 이렇게 해야 비밀번호를 바꾸더라도 로그아웃이 되지 않음
            return redirect('accounts:profile')
    else:
        form = UserChangeForm(instance=request.user)
    context = {
        'form' : form,
    }
    return render(request, 'accounts/update.html', context)

@login_required
def update_pw(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            user = User.objects.get(email=request.user.email)
            messages.success(request, 'Password changed successfully.')
            return redirect('accounts:profile')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'accounts/update_pw.html', {
        'form': form
    })

UserModel = get_user_model()

class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            {"title": self.title, "subtitle": None, **(self.extra_context or {})}
        )
        return context

INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"

class CustomPasswordResetConfirmView(PasswordContextMixin, FormView):
    # form_class = SetPasswordForm
    form_class = CustomSetPasswordForm
    post_reset_login = False
    post_reset_login_backend = None
    reset_url_token = "set-password"
    success_url = reverse_lazy("password_reset_complete")
    template_name = "registration/password_reset_confirm.html"
    title = _("Enter new password")
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        if "uidb64" not in kwargs or "token" not in kwargs:
            raise ImproperlyConfigured(
                "The URL path must contain 'uidb64' and 'token' parameters."
            )

        self.validlink = False
        self.user = self.get_user(kwargs["uidb64"])

        if self.user is not None:
            token = kwargs["token"]
            if token == self.reset_url_token:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(
                        token, self.reset_url_token
                    )
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            ValidationError,
        ):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            auth_login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context["validlink"] = True
        else:
            context.update(
                {
                    "form": None,
                    "title": _("Password reset unsuccessful"),
                    "validlink": False,
                }
            )
        return context