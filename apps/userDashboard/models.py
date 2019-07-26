from django.db import models
import bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class UserManager(models.Manager):
    #Verifies email and password for login, doesn't tell user what fails upon unsuccessful login
    def validator_login(self, postData):
        errors = {}
        if not EMAIL_REGEX.match(postData['sign_in_email']):
            errors['login'] = "Unable to log you in"
            return errors
        user = User.objects.filter(email = postData['sign_in_email'])
        print(user)
        if not user:
            errors['login'] = "Unable to log you in"
            return errors
        if bcrypt.checkpw(postData['sign_in_pass'].encode(), user[0].pw_hash.encode()):
            return errors
        errors['login'] = "Unable to log you in "
        return errors

    #Verifies password from the edit form as well as verifies previous password to make sure password change was intended
    def validator_password(self,postData):
        errors = {}
        if len(postData['edit_pass1']) < 8:
            errors['pass1'] = "Password must be at least 8 characters"
        if postData['edit_pass1'] != postData['edit_pass2']:
            errors['pass2'] = "Passwords must match"
        user = User.objects.get(id=postData['edit_id'])
        if bcrypt.checkpw(postData['edit_prev_pass'].encode(), user.pw_hash.encode()):
            return errors
        errors['prev_pass'] = "Your previous password doesn't match"
        return errors

        #Checks that profile edit doesn't leave blank areas or change email to something already taken        
    def validator_profile(self, postData):
        errors = {}
        if len(postData['edit_first_name']) < 2:
            errors['first'] = "First name must be two characters"
        if len(postData['edit_last_name']) < 2:
            errors['last'] = "Last name must be two characters"
        if not EMAIL_REGEX.match(postData['edit_email']):
            errors['email'] = "Must enter an email address"
        check_email = User.objects.filter(email=postData['edit_email'])
        print(check_email)
        if len(check_email) > 0:
            if check_email[0].id != int(postData['edit_id']):
                errors['email'] = "Email already taken"
        return errors

    #Checks registration, makes sure email is unique for each user for their login
    def validator_registration(self, postData):
        errors = {}
        if not EMAIL_REGEX.match(postData['register_email']):
            errors['email'] = "Must enter an email address"
        check_email = User.objects.filter(email=postData['register_email'])
        if len(check_email) > 0:
            errors['email'] = "Email already taken"
        if len(postData['register_first_name']) < 2:
            errors['first'] = "First name must be two characters"
        if len(postData['register_last_name']) < 2:
            errors['last'] = "Last name must be two characters"
        if len(postData['register_pass1']) < 8:
            errors['pass1'] = "Password must be at least 8 characters"
        if postData['register_pass1'] != postData['register_pass2']:
            errors['pass2'] = "Passwords must match"
        return errors

    def validator_change_password(self,postData):
        errors = {}
        if len(postData['edit_pass1']) < 8:
            errors['pass1'] = "Password must be at least 8 characters"
        if postData['edit_pass1'] != postData['edit_pass2']:
            errors['pass2'] = "Passwords must match"
        return errors


class User(models.Model):
    email = models.CharField(max_length = 255)
    first_name = models.CharField(max_length = 255)
    last_name = models.CharField(max_length = 255)
    pw_hash = models.CharField(max_length = 100)
    admin_level = models.CharField(max_length = 10)
    description = models.TextField(null = True)
    img_link = models.TextField(null = True)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    objects = UserManager()
    def __repr__(self):
        return(f"User object: {self.id} {self.first_name} {self.last_name} {self.email} {self.pw_hash} {self.admin_level}")

class Message(models.Model):
    message = models.TextField(null=True)
    sender = models.ForeignKey(User, related_name = "sent_by")
    receiver = models.ForeignKey(User, related_name = "received_by")
    read_status = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    def __repr__(self):
        return(f"Message object: {self.id} {self.message} {self.sender}")

class Comment(models.Model):
    comment = models.TextField(null=True)
    commenter = models.ForeignKey(User, related_name = "commented_by")
    recipient = models.ForeignKey(User, related_name = "commented_to", null=True)
    the_message = models.ForeignKey(Message, related_name = "comments", null=True)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    def __repr__(self):
        return(f"Comment object: {self.id} {self.comment} {self.commenter.first_name} {self.the_message}")

class Friend(models.Model):
    friend_requester = models.ForeignKey(User, related_name = "invited_by", null=True)
    request_to = models.ForeignKey(User, related_name = "invited_to", null=True)
    friends = models.ManyToManyField(User, related_name = "friends_with")
    #0 = pending, 1 = accepted
    acceptance = models.IntegerField(null=True)
    #0 = pending, 1 = rejected
    rejected = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    def __repr__(self):
        return(f"Friend object: {self.id} {self.friend_requester} {self.request_to} {self.friends}")