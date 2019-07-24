from django.shortcuts import render, redirect
from django.contrib import messages
from django.db.models import Count, Sum
from .models import User, UserManager, Message, Comment
import bcrypt

#Renders the add new user page
def add_new(request):
    return render(request, "userDashboard/add_user.html")

#Does verification for adding a new user similar to registration, making sure all fields are valid and the email is unique, gives prompt if successful
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

#Renders the dashboard for admins, allowing the edit/removal of users
def admin_dashboard(request):
    if request.session['user_id'] == None:
        return redirect('/')
    user = User.objects.get(id = request.session['user_id'])
    if user.admin_level == "superadmin" or user.admin_level == "admin": 
        users = User.objects.all()
        user_messages = Message.objects.filter(receiver = user).order_by('-created_at')[:3]
        total_unread = Message.objects.filter(receiver = user).filter(read_status = 0).annotate(count=Count('read_status'))
        context = {
        "users" : users,
        "user" : user,
        "user_messages" : user_messages,
        "total_unread" : total_unread
        }
        return render(request, "userDashboard/admin_dashboard.html", context)
    return redirect('/dashboard')

#Allows admin to edit passwords of admin_level lower than them. Won't allow the change of users with same admin_level
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

#Page for admin to see when they want to edit any user
def admin_edit_profile(request, user_id):
    curr_user = User.objects.get(id=request.session['user_id'])
    profile_user = User.objects.get(id = user_id)
    context = {
        'user': profile_user,
        'curr_user' : curr_user
    }
    return render(request, "userDashboard/admin_edit_profile.html", context)

#Page for admin to edit user profiles unless matching, but won't allow other admins unless of higher level to change other admins
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

#Adds comment to message
def comment(request, user_id, message_id):
    message = Message.objects.get(id=message_id)
    commenter = User.objects.get(id=request.session['user_id'])
    recipient = User.objects.get(id=user_id)
    new_comment = Comment.objects.create(comment=request.POST['comment_description'], commenter=commenter, recipient = recipient, the_message = message)
    return redirect(f'/profile/{user_id}')

#Regular dashboard for anyone
def dashboard(request):
    if request.session['user_id'] == None:
        return redirect('/')
    users = User.objects.all()
    context = {
        "users" : users
    }
    return render(request, "userDashboard/dashboard.html", context)

#Deletes comment from database
def delete_comment(request, comment_id, user_id):
    delete_comment = Comment.object.get(id=comment_id)
    delete_comment.delete()
    return redirect(f"/profile/{user_id}")
    
#Deletes message and related comments from database
def delete_message(request, message_id, user_id):
    delete_comments = Comment.objects.filter(the_message=message_id)
    delete_comments.delete()
    delete_message = Message.objects.get(id=message_id)
    delete_message.delete()
    return redirect(f"/profile/{user_id}")

#Allows admin to delete/remove users. Admin can only remove admin_levels lower than them, but no one can delete the original superadmin
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

#Renders the edit user page, only the user can edit their page
def edit(request):
    user = User.objects.get(id = request.session['user_id'])
    total_unread = Message.objects.filter(receiver = user).filter(read_status = 0).annotate(count=Count('read_status'))
    context = {
        'user': user,
        "total_unread" : total_unread
    }
    return render(request, "userDashboard/edit_profile.html", context)

#Allows user to change their description on their profile
def edit_description(request):
    user_update = User.objects.get(id = request.session['user_id'])
    user_update.description = request.POST['edit_description']
    user_update.save()
    messages.success(request, 'Description updated!', extra_tags = 'description')
    return redirect('/edit')

#Handles the edit passford form on the edit page, makes sure passwords match before updating
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

#Verifies use input to edit their profile, making sure email is unique. 
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

#Renders homepage
def home(request):
    return render(request, "userDashboard/home_page.html")

#Logs user out, removing all session variables
def logout(request):
    request.session['loggedin'] = False
    request.session['user_id'] = None
    return redirect('/')

#Sends new message to user in profile, sent read_status to 0 (unread)
def message(request, user_id):
    receiver = User.objects.get(id = user_id)
    sender = User.objects.get(id = request.session['user_id'])
    new_message = Message.objects.create(message=request.POST['message_description'], sender = sender, receiver = receiver, read_status = 0)
    messages.success(request, 'Message posted', extra_tags = 'add_message')
    return redirect (f'/profile/{user_id}')

#Renders profile page for each userid given, showing their messages and comments to those messages, if owner of account visits, sets message unread to 1 (read)
def profile(request, user_id):
    user = User.objects.get(id = user_id)
    curr_user = User.objects.get(id = request.session['user_id'])
    new_messages = Message.objects.filter(read_status = 0)
    if user.id == request.session['user_id']:
        for x in range (0, len(new_messages), 1):
            new_messages[x].read_status = 1
            new_messages[x].save()
    messages = Message.objects.filter(receiver=user).order_by("-created_at")
    comments = Comment.objects.filter(recipient=user)
    context = {
        "curr_user" : curr_user,
        "user" : user,
        "user_messages" : messages,
        "comments" : comments
    }
    return render(request, "userDashboard/profile.html", context)

#Renders register page
def register(request):
    return render(request, "userDashboard/registration.html")

#Verifies registration parameters and creates user if valid. First user created is always the "superadmin" and everyone after is "normal"
def register_user(request):
    errors = User.objects.validator_registration(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = key)
        return redirect('/registration')
    
    users = User.objects.all()
    if len(users) == 0:
        admin_level = "superadmin"
    else:
        admin_level = "normal"

    hash1 = bcrypt.hashpw(request.POST['register_pass1'].encode(), bcrypt.gensalt())
    request.session['loggedin'] = True
    new_user = User.objects.create(email = request.POST['register_email'], first_name = request.POST['register_first_name'], last_name = request.POST['register_last_name'], pw_hash = hash1, admin_level = admin_level)
    if new_user.admin_level == "superadmin":
        request.session['user_id'] = new_user.id
        return redirect('/dashboard/admin')
    else:
        request.session['user_id'] = new_user.id
        return redirect('/dashboard')

#Renders signin form
def signin(request):
    return render(request, "userDashboard/sign_in.html")

#Verifies user trying to sign in, returns them to signin page with error message if invalid
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

def unread_messages(request):
    user = User.objects.get(id = request.session['user_id'])
    new_messages = Message.objects.filter(read_status = 0)
    total_unread = Message.objects.filter(receiver = user).filter(read_status = 0).annotate(count=Count('read_status'))
    context = {
        "new_messages" : new_messages,
        "total_unread" : total_unread
    }
    return render(request, "UserDashboard/unread_messages.html", context)
