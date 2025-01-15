from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm, PasswordChangeForm
from django.contrib.auth.decorators import login_required

# View for handling user login
def login_view(request):
    """
    Handles user login functionality.
    If the request method is POST, it authenticates the user using the provided
    username/email and password. If authentication is successful, the user is logged in
    and redirected to the dashboard.
    If authentication fails, an error message is displayed.
    """
    if request.method == 'POST':
        username_or_email = request.POST['username_or_email']
        password = request.POST['password']

        # Authenticate user using the provided credentials
        user = authenticate(username=username_or_email, password=password)
        if user:
            login(request, user)
            messages.success(request, 'Successfully logged in!')
            return redirect('dashboard')  # Redirect to the dashboard after successful login
        else:
            messages.error(request, 'Invalid username/email or password.')  # Error if authentication fails

    return render(request, 'accounts/login.html')


# View for handling user signup
def signup_view(request):
    """
    Handles user signup functionality.
    If the request method is POST, it creates a new user account based on the provided
    username, email, and password. It also checks if the passwords match and ensures
    that the username and email are unique.
    Success and error messages are displayed accordingly.
    """
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        # Check if passwords match
        if password == confirm_password:
            # Check if the username or email already exists
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists.')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists.')
            else:
                # Create a new user if all checks pass
                User.objects.create_user(username=username, email=email, password=password)
                messages.success(request, 'Account created successfully! Please log in.')
                return redirect('login')  # Redirect to login page after successful signup
        else:
            messages.error(request, 'Passwords do not match.')  # Error if passwords do not match

    return render(request, 'accounts/signup.html')


# View for handling password reset functionality
def forgot_password_view(request):
    """
    Handles password reset functionality.
    If the request method is POST, it validates the provided email and sends a password reset
    email with a reset link to the user.
    Success and error messages are displayed accordingly.
    """
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            form.save(request=request, use_https=True)  # Send the reset email
            messages.success(request, 'Password reset instructions have been sent to your email.')
            return redirect('login')  # Redirect to login page after successful password reset request

    form = PasswordResetForm()
    return render(request, 'accounts/forgot_password.html', {'form': form})


# View for handling password change functionality
@login_required  # Ensure the user is logged in to access this page
def change_password_view(request):
    """
    Handles password change functionality for logged-in users.
    If the request method is POST, it validates the current password and the new password.
    If successful, the user's password is updated, and they remain logged in.
    Success and error messages are displayed accordingly.
    """
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()  # Save the new password
            update_session_auth_hash(request, user)  # Keep the user logged in
            messages.success(request, 'Your password has been changed successfully!')
            return redirect('dashboard')  # Redirect to the dashboard after successful password change
        else:
            messages.error(request, 'Please correct the errors below.')  # Error if form is invalid

    form = PasswordChangeForm(request.user)
    return render(request, 'accounts/change_password.html', {'form': form})


# View for the user's dashboard (only accessible when logged in)
@login_required  # Ensure the user is logged in to access this page
def dashboard_view(request):
    """
    Displays the user's dashboard.
    This page is only accessible to authenticated users.
    """
    return render(request, 'accounts/dashboard.html', {'user': request.user})


# View for the user's profile (only accessible when logged in)
@login_required  # Ensure the user is logged in to access this page
def profile_view(request):
    """
    Displays the user's profile page.
    This page is only accessible to authenticated users.
    """
    return render(request, 'accounts/profile.html', {'user': request.user})


# View for logging out the user
def logout_view(request):
    """
    Logs the user out and redirects them to the login page.
    A success message is displayed after the logout.
    """
    logout(request)  # Logs the user out
    messages.success(request, 'You have been logged out.')
    return redirect('login')  # Redirect to the login page after logging out
