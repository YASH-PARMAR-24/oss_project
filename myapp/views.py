from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages, auth
from django.urls import reverse

# Login view with @login_required decorator
@login_required(login_url='login')
def home(request):
    return render(request, 'home.html')

# Logout view
def logout_view(request):
    auth.logout(request)
    messages.success(request, "You have been logged out.")
    return redirect("/")

# Logout page view with @login_required decorator
@login_required(login_url='login')
def logoutpage(request):
    logout(request)
    return redirect('login')

# Login view
def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            auth_login(request, user)
            return redirect('home')
        else:
            error_message = "Incorrect email or password. Please try again."
            return render(request, 'login.html', {'error_message': error_message})

    return render(request, 'login.html')

# Sign-up view
def sign_up(request):
    if request.method == 'POST':
        firstname = request.POST.get('firstName')
        lastname = request.POST.get('lastName')
        uname = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('password')
        pass2 = request.POST.get('confirmPassword')

        if pass1 != pass2:
            return HttpResponse("Your password and confirmed password do not match.")
        else:
            try:
                my_user = User.objects.create_user(username=uname, email=email, password=pass1)
                my_user.first_name = firstname
                my_user.last_name = lastname
                my_user.save()

                return redirect('login')

            except IntegrityError:
                error_message = "Username already exists. Please choose a different username."
                return render(request, 'sign_up.html', {'error_message': error_message})

    return render(request, 'sign_up.html')
