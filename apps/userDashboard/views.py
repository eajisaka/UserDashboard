from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User, UserManager, Message, Comment
import bcrypt

def home(request):
    return render(request, "userDashboard/home_page.html")

def register(request):
    return render(request, "userDashboard/registration.html")

def register_user(request):
    errors = User.objects.validator_registration(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = key)
        return redirect('/registration')
    
    users = User.objects.all()
    admin = 0
    if len(users) == 0:
        admin = "superadmin"
    else:
        admin = "normal"

    hash1 = bcrypt.hashpw(request.POST['register_pass1'].encode(), bcrypt.gensalt())
    request.session['loggedin'] = True
    new_user = User.objects.create(email = request.POST['register_email'], first_name = request.POST['register_first_name'], last_name = request.POST['register_last_name'], pw_hash = hash1, admin_level = admin)
    if admin == "admin":
        request.session['user_id'] = new_user.id
        return redirect('/dashboard/admin')
    else:
        request.session['user_id'] = new_user.id
        return redirect('/dashboard')

def signin(request):
    return render(request, "userDashboard/sign_in.html")

def signin_user(request):
    errors = User.objects.validator_login(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = key)
        return redirect('/signin')
    request.session['loggedin'] = True
    user = User.objects.get(email=request.POST['sign_in_email'])
    request.session['user_id'] = user.id
    if user.admin_level == "superadmin" or user.admin_level =="admin":
        return redirect('/dashboard/admin')
    return redirect('/dashboard')

def dashboard(request):
    if request.session['user_id'] == None:
        return redirect('/')
    users = User.objects.all()
    context = {
        "users" : users
    }
    return render(request, "userDashboard/dashboard.html", context)

def admin_dashboard(request):
    if request.session['user_id'] == None:
        return redirect('/')
    user = User.objects.get(id = request.session['user_id'])
    if user.admin_level == "superadmin" or user.admin_level == "admin": 
        users = User.objects.all()
        context = {
        "users" : users,
        "user" : user
        }
        return render(request, "userDashboard/admin_dashboard.html", context)
    return redirect('/dashboard')

def logout(request):
    request.session['loggedin'] = False
    request.session['user_id'] = None
    return redirect('/')

def message(request, user_id):
    print("now in message view!")
    receiver = User.objects.get(id = user_id)
    sender = User.objects.get(id = request.session['user_id'])
    new_message = Message.objects.create(message=request.POST['message_description'], sender = sender, receiver = receiver)
    messages.success(request, 'Message posted', extra_tags = 'add_message')
    return redirect (f'/profile/{user_id}')

def add_new(request):
    return render(request, "userDashboard/add_user.html")

def comment(request, user_id, message_id):
    message = Message.objects.get(id=message_id)
    print(f'{message.id} + {message.sender.first_name}')
    commenter = User.objects.get(id=request.session['user_id'])
    print(f'{commenter.id} + {commenter.first_name}')
    recipient = User.objects.get(id=user_id)
    new_comment = Comment.objects.create(comment=request.POST['comment_description'], commenter=commenter, recipient = recipient, the_message = message)
    return redirect(f'/profile/{user_id}')

def profile(request, user_id):
    user = User.objects.get(id = user_id)
    messages = Message.objects.filter(receiver=user)
    comments = Comment.objects.filter(recipient=user)
    context = {
        "user" : user,
        "user_messages" : messages,
        "comments" : comments
    }
    return render(request, "userDashboard/profile.html", context)

def add_user(request):
    errors = User.objects.validator_registration(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = key)
        return redirect('/add_new')
    hash1 = bcrypt.hashpw(request.POST['register_pass1'].encode(), bcrypt.gensalt())
    new_user = User.objects.create(email = request.POST['register_email'], first_name = request.POST['register_first_name'], last_name = request.POST['register_last_name'], pw_hash = hash1, admin_level = "normal")
    messages.success(request, 'User added', extra_tags = 'add_user')
    return redirect('/add_new')

def edit(request):
    user = User.objects.get(id = request.session['user_id'])
    context = {
        'user': user
    }
    return render(request, "userDashboard/edit_profile.html", context)

def edit_password(request):
    errors = User.objects.validator_password(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = key)
        return redirect('/edit')
    hash1 = bcrypt.hashpw(request.POST['edit_pass1'].encode(), bcrypt.gensalt())
    user_update = User.objects.get(id=request.POST['edit_id'])
    user_update.pw_hash = hash1
    user_update.save()
    messages.success(request, 'Password updated!', extra_tags = 'password')
    return redirect('/edit')

def edit_description(request):
    user_update = User.objects.get(id = request.session['user_id'])
    user_update.description = request.POST['edit_description']
    user_update.save()
    messages.success(request, 'Description updated!', extra_tags = 'description')
    return redirect('/edit')

def admin_edit_profile(request, user_id):
    curr_user = User.objects.get(id=request.session['user_id'])
    profile_user = User.objects.get(id = user_id)
    context = {
        'user': profile_user,
        'curr_user' : curr_user
    }
    return render(request, "userDashboard/admin_edit_profile.html", context)

def delete_user(request, user_id):
    if request.session['user_id'] == None:
        return redirect('/')
    curr_user = User.objects.get(id =request.session['user_id'])
    remove_user = User.objects.get(id = user_id)
    if remove_user.id == 1 and remove_user.admin_level=="superadmin":
        messages.error(request, "You can't delete the head honcho superadmin!", extra_tags = "delete_error")
        return redirect('/dashboard/admin')
    if curr_user.admin_level != "superadmin":
        messages.error(request, "You can't delete another admin!", extra_tags = "delete_error")
        return redirect('/dashboard/admin')
    if remove_user.admin_level == "superadmin":
            messages.error(request, "You can't delete another superadmin!", extra_tags = "delete_error")
            return redirect('/dashboard/admin')
        
    remove_user.delete()
    return redirect('/dashboard/admin')

def admin_edit_password(request, user_id):
    errors = User.objects.validator_change_password(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = key)
        return redirect(f'/edit/profile/{user_id}')
    curr_user = User.objects.get(id =request.session['user_id'])
    user_update = User.objects.get(id = user_id)
    if user_update.admin_level == "superadmin" or user_update.admin_level =="admin":
        if curr_user.admin_level =="superadmin" and curr_user.id == 1:
            hash1 = bcrypt.hashpw(request.POST['edit_pass1'].encode(), bcrypt.gensalt())
            user_update.pw_hash = hash1
            user_update.save()
            messages.success(request, 'Password updated!', extra_tags = 'password')
            return redirect(f'/edit/profile/{user_id}')
        if curr_user.admin_level != "superadmin" and user_update.id != request.session['user_id']:
            messages.error(request, "You can't change other admins' passwords!", extra_tags = 'edit_pass_error')
            return redirect(f'/edit/profile/{user_id}')
    hash1 = bcrypt.hashpw(request.POST['edit_pass1'].encode(), bcrypt.gensalt())
    user_update.pw_hash = hash1
    user_update.save()
    messages.success(request, 'Password updated!', extra_tags = 'password')
    return redirect(f'/edit/profile/{user_id}')

def admin_edit_user(request, user_id):
    errors = User.objects.validator_profile(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = key)
        return redirect(f'/edit/profile/{user_id}')
    curr_user = User.objects.get(id =request.session['user_id'])
    user_update = User.objects.get(id=user_id)
    if user_update.admin_level == "superadmin" or user_update.admin_level =="admin":
        if curr_user.admin_level =="superadmin" and curr_user.id == 1:
            user_update.email = request.POST['edit_email']
            user_update.first_name = request.POST['edit_first_name']
            user_update.last_name = request.POST['edit_last_name']
            user_update.admin_level = request.POST['edit_user_level']
            user_update.save()
            messages.success(request, 'Profile updated!', extra_tags = 'profile')
            return redirect(f'/edit/profile/{user_id}')
        if curr_user.admin_level != "superadmin" or user_update.id != request.session['user_id']:
            messages.error(request, "You can't change other admins' information!", extra_tags = 'edit_error')
            return redirect(f'/edit/profile/{user_id}')
    user_update.email = request.POST['edit_email']
    user_update.first_name = request.POST['edit_first_name']
    user_update.last_name = request.POST['edit_last_name']
    user_update.admin_level = request.POST['edit_user_level']
    user_update.save()
    messages.success(request, 'Profile updated!', extra_tags = 'profile')
    return redirect(f'/edit/profile/{user_id}')


def edit_user(request):
    errors = User.objects.validator_profile(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = key)
        return redirect('/edit')
    user_update = User.objects.get(id=request.session['user_id'])
    user_update.email = request.POST['edit_email']
    user_update.first_name = request.POST['edit_first_name']
    user_update.last_name = request.POST['edit_last_name']
    user_update.save()
    messages.success(request, 'Profile updated!', extra_tags = "profile")
    return redirect('/edit')