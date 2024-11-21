from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from .models import Profile
from .forms import CustomUserCreationForm
def loginUser(request):
    page = 'login'

    if request.user.is_authenticated:
        return redirect('profiles')

    """
    Handles user login request. If the request method is POST, it retrieves the username and password
    from the request, attempts to authenticate the user, and logs them in if successful. If the user
    does not exist or the credentials are incorrect, an error message is printed. Finally, it renders
    the login/register template.
    """
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        try:
            user = Profile.objects.get(username=username)
        except:
            messages.error(request, "User does not exist")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('profiles')

        else:
            messages.error(request, "Username or password is incorrect")

    return render(request, 'users/login_register.html')



def logoutUser(request):
        logout(request)
        messages.error(request, "User was logged out")
        return redirect('login')

def registerUser(request):
    page = 'register'
    form = CustomUserCreationForm()

    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.username = user.username.lower()
            user.save()
            login(request, user)
            return redirect('profiles')

            messages.success(request, 'User account was created!')
        else:
            messages.error(request, 'Invalid form data')    

            #login(request, user)
            #return redirect('profiles')

    context = {'page' : page, 'form': form}
    return render(request, 'users/login_register.html', context)
# Create your views here.
def profiles(request):
    profiles = Profile.objects.all()
    context = {'profiles': profiles}
    return render(request, 'users/profiles.html', context)

def userProfile(request, pk):
    profile = Profile.objects.get(id=pk)

    topSkills = profile.skill_set.exclude(description__exact="")
    otherSkills = profile.skill_set.filter(description="")


    context = {'profile': profile, 'topSkills': topSkills, "otherSkills":otherSkills}
    return render(request, 'users/user-profile.html', context)