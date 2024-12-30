from django.shortcuts import render, redirect
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.conf import settings
from django.urls import reverse
from .forms import MagicLinkForm
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from .forms import RegistrationForm
from django.contrib.auth import logout
from django_ratelimit.decorators import ratelimit
from django.http import JsonResponse







User = get_user_model()







signer = TimestampSigner()  # To sign and validate tokens


def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')  # Redirect to login page after successful registration
    else:
        form = RegistrationForm()
    return render(request, 'pages/register.html', {'form': form})







def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                return redirect('home')  # Redirect to home page after login
            else:
                return render(request, 'pages/login.html', {'form': form, 'error': 'Invalid username or password'})
        else:
            return render(request, 'pages/login.html', {'form': form, 'error': 'Form is not valid'})

    else:
        form = AuthenticationForm()
    return render(request, 'pages/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to login page after logout




@ratelimit(key='ip', rate='2/m', method='ALL', block=False)
def request_magic_link(request):
    if getattr(request, 'limited', False):
        logger.error("Rate limit exceeded for IP: %s", request.META.get('REMOTE_ADDR'))
        return render(request, 'pages/magic_link_request.html', {
            'form': MagicLinkForm(),
            'error': "Rate limit exceeded. Please try again later."
        })

    if request.method == 'POST':
        form = MagicLinkForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            # Check if the email exists in the database
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return render(request, 'pages/magic_link_request.html', {
                    'form': form,
                    'error': "No user found with this email."
                })

            # Generate a signed token
            token = signer.sign(user.id)

            # Construct the magic link
            magic_link = request.build_absolute_uri(reverse('magic_login') + f'?token={token}')

            # Send the magic link via email
            send_mail(
                subject="Your Magic Login Link",
                message=f"Click the link below to log in:\n\n{magic_link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
            )

            return render(request, 'pages/magic_link_request.html', {
                'form': form,
                'message': "Magic link sent! Please check your email."
            })

    else:
        form = MagicLinkForm()

    return render(request, 'pages/magic_link_request.html', {'form': form})




def magic_login(request):
    token = request.GET.get('token')
    if not token:
        return render(request, 'pages/error.html', {'error': 'Invalid or missing token.'})

    if getattr(request, 'limited', False):
        return JsonResponse({'error': 'Rate limit exceeded'}, status=429)

    try:
        # Verify the token
        user_id = signer.unsign(token, max_age=600)  # Token expires after 10 minutes
        user = User.objects.get(id=user_id)

        # Log in the user
        login(request, user)
        return redirect('home')

    except (BadSignature, SignatureExpired, User.DoesNotExist):
        return render(request, 'pages/error.html', {'error': 'The token is invalid or expired.'})


