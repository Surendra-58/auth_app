# from django.shortcuts import render, redirect
# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.decorators import login_required
# from django.contrib import messages
# import uuid
# from django.conf import settings
# from django.core.mail import EmailMessage
# from django.utils import timezone
# from django.urls import reverse
# from .models import *


# # Create your views here.


# @login_required
# def Home(request):
#     print("User:", request.user, "Authenticated:", request.user.is_authenticated)
#     return render(request, 'index.html')

# def RegisterView(request):

#     if request.method == 'POST':
#         # getting user input from frontend
#         first_name = request.POST.get('fname')
#         last_name = request.POST.get('lname')
#         user_name = request.POST.get('uname')
#         user_email = request.POST.get('email')
#         user_password = request.POST.get('password')

#         user_data_has_error = False
    
#         if User.objects.filter(username=user_name).exists():
#             user_data_has_error = True
#             messages.error(request, "Username already exists")

#         if User.objects.filter(email=user_email).exists():
#             user_data_has_error = True
#             messages.error(request, "Email already exists")
        
#         if len(user_password) < 5:
#             user_data_has_error = True
#             messages.error(request, "Password must be at least 5 character")
        
#         if user_data_has_error:
#             return redirect('register')
        
#         else:
#             new_user = User.objects.create_user(
#                 first_name=first_name,
#                 last_name=last_name,
#                 email=user_email,
#                 username=user_name,
#                 password=user_password
#             )
#             messages.success(request, "Account created. Login now")
#             return redirect('login')
        
#     return render(request, 'register.html')


    

# def LoginView(request):

#     if request.method == "POST":
#         username = request.POST.get("uname")
#         password = request.POST.get("password")

#         user = authenticate(request, username=username, password=password)

#         if user is not None:
#             login(request, user)

#             return redirect('home')
        
#         else:
#             messages.error(request, "Invalid login credentials") 
#             return redirect('login')
    
#     return render(request, 'login.html')

# def LogoutView(request):

#     logout(request)

#     return redirect('login')

# def ForgetPassword(request):

#     if request.method == 'POST':
#         email = request.POST.get('email')

#         try:
#             user = User.objects.get(email=email)
#             #user = User.objects.only('id').get(email=email)
#             #this will optimize code. help faster performance
#             new_password_reset = PasswordReset(user=user)
#             new_password_reset.save()

#             password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})
#             full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

#             email_body = f'From Surendra\n Reset your password using the link below:\n\n\n{full_password_reset_url}'

#             email_message = EmailMessage(
#                 'Reset your password', # email subject
#                 email_body,
#                 settings.EMAIL_HOST_USER,  #email sender
#                 [email] #email receiver

#             )

#             email_message.fail_silently = True
#             email_message.send()

#             return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)
        
#         except User.DoesNotExist:
#             print("no user found")
#             messages.error(request, f"No user with email '{email}' found")
#             return redirect('forget-password')
    
#     return render(request, 'forget.html')




# def PasswordResetSent(request, reset_id):
#     if PasswordReset.objects.filter(reset_id=reset_id).exists():
#         return render(request, 'password-reset-sent.html')
#     else:
#         # refirect to forget password page if code does not exist
#         messages.error(request, 'Invalid reset id')
#         print("your reset_id is wrong")
#         return redirect('forget-password')
    

# def ResetPassword(request, reset_id):

#     try:
#         # Validate the reset_id as a UUID version 4
#         uuid_obj = uuid.UUID(reset_id, version=4)
#     except ValueError:
#         # If it's not a valid UUID, redirect to 'forget-password' page
#         messages.error(request, 'Invalid reset id')
#         return redirect('forget-password')

#     try:
#         password_reset_id = PasswordReset.objects.get(reset_id=reset_id)
#         if request.method == "POST":
#             password = request.POST.get('password')
#             confirm_password = request.POST.get('confirm_password')
#             expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=2)

#             if timezone.now() > expiration_time:
#                 passwords_have_error = True
#                 messages.error(request, 'Reset link has expired')
#                 password_reset_id.delete()
#                 return redirect('forget-password')

#             if request.method == 'POST':
#                 password = request.POST.get('password')
#                 confirm_password = request.POST.get('confirm_password')

#                 passwords_have_error = False

#             if password != confirm_password:
#                 passwords_have_error = True
#                 messages.error(request, 'Passwords do not match')
            
#             if len(password) < 5:
#                 passwords_have_error = True
#                 messages.error(request, 'Password must be at least 5 charcters long')


            
#             if not passwords_have_error:
#                 user = password_reset_id.user
#                 user.set_password(password)
#                 user.save()

#                 password_reset_id.delete()

#                 messages.success(request, 'Password reset. Proceed to login')
#                 return redirect('login')
#             else:
#                 #redirect back to password reset page and display errors
#                 return redirect('reset-password', reset_id=reset_id)
            
#     except PasswordReset.DoesNotExist:

#         #redirect to forget password page if code does not exist
#         return redirect('forget-password')
    
#     return render(request, 'reset-password.html')






from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from django.core import signing
from django.core.signing import BadSignature, SignatureExpired
from .models import PasswordReset

TOKEN_EXPIRY_MINUTES = 2  # Token expiry time

@login_required
def Home(request):
    print("User:", request.user, "Authenticated:", request.user.is_authenticated)
    return render(request, 'index.html')

def RegisterView(request):
    if request.method == 'POST':
        first_name = request.POST.get('fname')
        last_name = request.POST.get('lname')
        user_name = request.POST.get('uname')
        user_email = request.POST.get('email')
        user_password = request.POST.get('password')

        user_data_has_error = False

        if User.objects.filter(username=user_name).exists():
            user_data_has_error = True
            messages.error(request, "Username already exists")

        if User.objects.filter(email=user_email).exists():
            user_data_has_error = True
            messages.error(request, "Email already exists")

        if len(user_password) < 5:
            user_data_has_error = True
            messages.error(request, "Password must be at least 5 characters long")

        if user_data_has_error:
            return redirect('register')

        new_user = User.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            email=user_email,
            username=user_name,
            password=user_password
        )
        messages.success(request, "Account created. Login now")
        return redirect('login')

    return render(request, 'register.html')

def LoginView(request):
    if request.method == "POST":
        username = request.POST.get("uname")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('home')

        messages.error(request, "Invalid login credentials")
        return redirect('login')

    return render(request, 'login.html')

def LogoutView(request):
    logout(request)
    return redirect('login')

def ForgetPassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)
            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            # Generate a signed token with reset_id and timestamp
            reset_data = {'reset_id': str(new_password_reset.reset_id), 'timestamp': timezone.now().timestamp()}
            signed_token = signing.dumps(reset_data)

            password_reset_url = reverse('reset-password', kwargs={'signed_token': signed_token})
            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            #email_body = f'Reset your password using the link below:\n\n{full_password_reset_url}'
                        # HTML Email Message
            html_message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        margin: 0;
                        padding: 0;
                    }}
                    .container {{
                        width: 100%;
                        max-width: 600px;
                        margin: 20px auto;
                        background: #ffffff;
                        padding: 20px;
                        border-radius: 10px;
                        box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
                    }}
                    h2 {{
                        color: #007bff;
                        text-align: center;
                    }}
                    p {{
                        font-size: 16px;
                        color: #333;
                        line-height: 1.6;
                    }}
                    .highlight {{
                        font-weight: bold;
                        color: #d9534f;
                    }}
                    .footer {{
                        text-align: center;
                        font-size: 14px;
                        color: #777;
                        margin-top: 20px;
                    }}
                    .button {{
                        display: inline-block;
                        padding: 10px 15px;
                        margin-top: 15px;
                        color: #fff;
                        background: #28a745;
                        text-decoration: none;
                        border-radius: 5px;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>🔐 Password Reset Request</h2>
                    
                    <p>Hello dear teammate,</p>

                    <p>I am <strong>Surendra Raj Bisht</strong>. First, I want to express my gratitude for checking whether this <span class="highlight">Forget Password</span> function works as expected.</p>

                    <p style="background-color:yellow;">I am very thankful for viewing this project.</p>
                    <p>Your role is crucial in making the system more efficient. I request you to design the <span class="highlight">frontend template</span> to make it visually appealing and highly interactive</p>
                    
                    <p>Please use the button below to reset your password:</p>

                    <p style="text-align: center;">
                    <a href="{full_password_reset_url}" class="button">Reset Password</a>
                    </p>

                    <p>If you did not request this, please ignore this email.</p>

                    <div class="footer">
                        <p>Best regards,<br>Surendra Raj Bisht</p>
                    </div>
                </div>
            </body>
            </html>
            """

            email_message = EmailMessage(
                '🔐 Password Reset Request',  #email subject
                html_message,  #email body
                settings.EMAIL_HOST_USER,  #Sender
                [email]  #Recipient
            )
            email_message.content_subtype = "html" #Make it as an HTML email
            email_message.fail_silently = True
            email_message.send()

            return redirect('password-reset-sent')

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forget-password')

    return render(request, 'forget.html')

def PasswordResetSent(request):
    return render(request, 'password-reset-sent.html')

def ResetPassword(request, signed_token):
    try:
        # Validate and decode the signed token
        reset_data = signing.loads(signed_token, max_age=TOKEN_EXPIRY_MINUTES * 60)
        reset_id = reset_data.get('reset_id')

        password_reset_entry = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            if password != confirm_password:
                messages.error(request, 'Passwords do not match')
            elif len(password) < 5:
                messages.error(request, 'Password must be at least 5 characters long')
            else:
                user = password_reset_entry.user
                user.set_password(password)
                user.save()

                # Remove used reset entry
                password_reset_entry.delete()

                messages.success(request, 'Password reset successfully. You can now log in.')
                return redirect('login')

            return redirect('reset-password', signed_token=signed_token)

    except (BadSignature, SignatureExpired, PasswordReset.DoesNotExist):
        messages.error(request, 'Invalid or expired reset link')
        return redirect('forget-password')

    return render(request, 'reset-password.html')
