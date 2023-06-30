#!/usr/bin/env python3
from datetime import datetime, timedelta
import hashlib
from flask import Flask, render_template, request, jsonify, redirect, Response, url_for, send_from_directory, session
from pymongo import MongoClient
from flask_mongoengine import MongoEngine
from flask_login import current_user, login_required, login_user, logout_user, confirm_login, fresh_login_required
from flask_login import LoginManager, UserMixin
import os
import yaml
from random import random
import re
import time
import json
import jinja2
from flask_mail import Mail, Message
from random import choice
from string import ascii_uppercase, digits
from flask_talisman import Talisman
import shutil
import cloudgenix
from cloudgenix import jd, jd_detailed
import threading
from threading import Thread, Event
from csv import DictReader
from flask_socketio import SocketIO, emit, join_room, leave_room
import base64
import csv
from werkzeug.utils import secure_filename
import requests
import urllib3
from files.do_one import go_do_one
from files.do_two import go_do_two
from files.pull_one import go_pull_one
from files.pull_two import go_pull_two

urllib3.disable_warnings()

app = Flask(__name__)

from gevent import monkey
monkey.patch_all()

##############################################
######## Credentials and API Version #########
##############################################

SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", None)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "PrismaSDWAN")
MONGODB_DATABASE = os.environ.get("MONGODB_DATABASE", "flaskdb")
MONGODB_USERNAME = os.environ.get("MONGODB_USERNAME", "flaskuser")
MONGODB_PASSWORD = os.environ.get("MONGODB_PASSWORD", "PrismaSDWAN")
SDWAN_CONTROLLER = None
SDWAN_SSL_VERIFY = True
SITE_API = "4.7"

##############################################
######## Flask and SocketIO Setup ############
##############################################

socketio = SocketIO(app, cors_allowed_origins="*")

login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = "site-automation"

##############################################
########## Mongodb Collections ###############
##############################################

app.config['MONGODB_SETTINGS'] = {'MONGODB_HOST': 'mongodb://' + MONGODB_USERNAME + ':' + MONGODB_PASSWORD + '@mongodb/' + MONGODB_DATABASE + '?retryWrites=true&w=majority',}
db = MongoEngine(app)

QUEUE_NAME = "deploy"

class Users(UserMixin, db.Document):
    username = db.StringField()
    first = db.StringField()
    last = db.StringField()
    password = db.StringField()
    reset_pw = db.BooleanField()
    auth = db.StringField()
    auth_valid = db.BooleanField()
    tenant = db.StringField()
    register_date = db.DateTimeField()
    last_login = db.DateTimeField()
    active = db.BooleanField()
    process = db.BooleanField()
    directory = db.StringField()
    local_storage = db.StringField()
    log = db.StringField()
    custom_build = db.ListField()
    logins = db.IntField()
    custom_tools = db.ListField()
    ip_address = db.StringField()

class Metrics(db.Document):
    year = db.IntField()
    month = db.IntField()
    logins = db.IntField()
    tasks = db.IntField()
    job = db.ListField()

class Files(db.Document):
    owner = db.StringField()
    name = db.StringField()
    type = db.StringField()
    content = db.StringField()
    csv = db.ListField()
    
class Site(db.Document):
    username = db.StringField()
    site_names = db.ListField()
    site_tags = db.ListField()
    csv_name = db.StringField()
    csv_site_names = db.ListField()
    make_file = db.StringField()
    make_csv = db.ListField()
    image_options = db.ListField()
    machines = db.ListField()
    domains = db.ListField()
    publicwan = db.ListField()
    privatewan = db.ListField()
    elements = db.ListField()

class Queues(db.Document):
    name = db.StringField()
    do_in_use = db.BooleanField()
    do_current_user_one = db.StringField()
    do_current_user_two = db.StringField()
    do_user_queue = db.ListField()
    pull_in_use = db.BooleanField()
    pull_current_user_one = db.StringField()
    pull_current_user_two = db.StringField()
    pull_user_queue = db.ListField()
    registration_lock = db.BooleanField()

##############################################
########## Update/Create Metric Log ##########
##############################################

def metric_update():
    try:
        currentYear = datetime.now().year
        currentMonth = datetime.now().month
        if Metrics.objects(year=currentYear, month=currentMonth):
            update = Metrics.objects(year=currentYear, month=currentMonth).first()
            logins = update["logins"]
            logins += 1
            update["logins"] = logins
            update.save()
        else:
            job = []
            add = Metrics(year=currentYear, month=currentMonth, logins=1, tasks=0, job=job)
            add.save()
    except:
        print("Failed to create or update metrics logins")
    return

def metric_update_tasks(payload_dict):
    try:
        currentYear = datetime.now().year
        currentMonth = datetime.now().month
        if Metrics.objects(year=currentYear, month=currentMonth):
            update = Metrics.objects(year=currentYear, month=currentMonth).first()
            tasks = update["tasks"]
            tasks += 1
            job = update["job"]
            job_string = str(payload_dict["username"]) + " ran " + str(payload_dict["job"]) + "v16 at " + str(datetime.now())
            job.append(job_string)
            update["tasks"] = tasks
            update["job"] = job
            update.save()
        else:
            job = []
            job_string = str(payload_dict["username"]) + " ran " + str(payload_dict["job"]) + "v16 at " + str(datetime.now())
            job.append(job_string)
            add = Metrics(year=currentYear, month=currentMonth, logins=0, tasks=1, job=job)
            add.save()
    except:
        print("Failed to create or update metric tasks")
    return

##############################################
########## Create ADMIN User #################
##############################################

def create_admin_user():
    try:
        salt = "prisma"
        if Users.objects(username=ADMIN_USERNAME).first():
            update = Users.objects(username=ADMIN_USERNAME).first()
            db_password = ADMIN_PASSWORD + salt
            hash = hashlib.md5(db_password.encode())
            hash = hash.hexdigest()
            update["password"] = hash
            update.save()
            print("Updating admin user")
        else:
            new_user = Users()
            new_user["first"] = "Admin"
            new_user["last"] = ""
            new_user["username"] = ADMIN_USERNAME
            db_password = ADMIN_PASSWORD + salt
            hash = hashlib.md5(db_password.encode())
            hash = hash.hexdigest()
            new_user["password"] = hash
            new_user["auth"] = "None"
            new_user["register_date"] = datetime.now()
            time = datetime.now()
            new_user["active"] = True
            new_user["last_login"] = datetime.now()
            new_user["logins"] = 0
            directory = ADMIN_USERNAME
            new_user["directory"] = directory
            log = "/var/www/storage/" + directory + "/" + directory + "-log.txt"
            local_storage = "/var/www/storage/" + directory + "/"
            new_user["local_storage"] = local_storage
            new_user["log"] = log
            new_user["process"] = False
            new_user["auth_valid"] = False
            new_user["ip_address"] = "None"
            new_user["custom_tools"] = ["None"]
            custom_build = []
            custom_build.append("Standard")
            new_user["custom_build"] = custom_build
            new_user.save()
            print("Created admin user")
    except Exception as e:
        print("Failed to create admin user")
        print(str(e))
    return

##############################################
########## Create Server DB ##################
##############################################

def create_queue_db():
    try:
        if Queues.objects(name=QUEUE_NAME):
            update = Queues.objects(name=QUEUE_NAME).first()
            blank = []
            update["do_in_use"] = False
            update["do_current_user_one"] = "None"
            update["do_current_user_two"] = "None"
            update["do_user_queue"] = blank
            update["pull_in_use"] = False
            update["pull_current_user_one"] = "None"
            update["pull_current_user_two"] = "None"
            update["pull_user_queue"] = blank
            update.save()
            print("Updating queue database")
        else:
            blank = []
            add = Queues(name=QUEUE_NAME, do_in_use=False, do_current_user_one="None", do_current_user_two="None", do_user_queue=blank, pull_in_use=False, pull_current_user_one="None", pull_current_user_two="None", pull_user_queue=blank, registration_lock=False)
            add.save()
            print("Created queue database")
    except:
        print("Failed to queue database")
    return

##############################################
################ Check Auth ##################
##############################################

def auth_check(auth):
    try:
        cgx_session = cloudgenix.API(controller=SDWAN_CONTROLLER, ssl_verify=SDWAN_SSL_VERIFY, update_check=False)
        cgx_session.interactive.use_token(auth)
        if cgx_session.tenant_name:
            auth_valid = True
            tenant = cgx_session.tenant_name
            cgx_session.get.logout()
            return auth_valid, tenant
        else:
            auth_valid = False
            tenant = "None"
            return auth_valid, tenant
    except:
        auth_valid = False
        tenant = "None"
        return auth_valid, tenant

##############################################
################ Save File ###################
##############################################

def delete_file(username, filename):
    files = Files.objects(owner=username)
    for item in files:
        if item["name"] == filename:
            item.delete()
    return
    
def file_download(username, filename):
    user = Users.objects(username=username).first()
    temp = user["local_storage"]
    ext = os.path.splitext(filename)[-1].lower()
    ext = ext[1:]
    files = Files.objects(owner=username)
    for item in files:
        if item["name"] == filename:
            file_found = item
            break
    filepath = os.path.join(temp, filename)
    if ext == "csv":
        csv_columns = []
        for key in file_found["csv"][0]:
            csv_columns.append(key)
        with open(filepath, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in file_found["csv"]:
                writer.writerow(data)
    elif ext == "jinja" or ext == "yaml":
        f = open(filepath, "w")
        f.write(file_found["content"])
        f.close()
    return filepath

def save_file(file, filename, ext, username):
    user = Users.objects(username=username).first()
    files = Files.objects(owner=username)
    temp = user["local_storage"]
    filepath = os.path.join(temp, filename)
    file.save(filepath)
    if ext == "csv":
        with open(filepath, 'r') as read_obj:
            csv_dict_reader = DictReader(read_obj)
            sites = []
            for row in csv_dict_reader:
                sites.append(row)
    elif ext == "jinja" or ext == "yaml":
        file_temp = open(filepath, "r")
        file_content = file_temp.read()
    file_check = True
    for item in files:
        if item["name"] == filename:
            file_check=False
            item["type"] = ext
            if ext == "csv":
                item["csv"] = sites
            elif ext == "jinja" or ext == "yaml":
                item["content"] = file_content
            item.save()
            break
    if file_check:
        if ext == "csv":
             csv = sites
             file_db = Files(owner=username, name=filename, type=ext, content="None", csv=sites)
        elif ext == "jinja" or ext == "yaml":
            blank = []
            file_db = Files(owner=username, name=filename, type=ext, content=file_content, csv=blank) 
        file_db.save()
    try:
        os.remove(filepath)
    except:
        print("File is not local")
    return

def save_backup(filepath, filename, ext, username):
    files = Files.objects(owner=username)
    
    file_temp = open(filepath, "r")
    file_content = file_temp.read()
    
    file_check = True
    filename = filename.replace(".yaml", "-backup.yaml" )
    for item in files:
        if item["name"] == filename:
            file_check = False
            item["type"] = ext
            item["content"] = file_content
            item.save()
    if file_check:
        blank = []
        file_db = Files(owner=username, name=filename, type=ext, content=file_content, csv=blank)
        file_db.save()
    return

def make_save_file(file_content, filename, ext, username):
    files = Files.objects(owner=username)    
    file_check = True
    for item in files:
        if item["name"] == filename:
            file_check=False
            item["type"] = ext
            item["content"] = file_content
            item.save()
            break
    if file_check:
        blank = []
        file_db = Files(owner=username, name=filename, type=ext, content=file_content, csv=blank)
        file_db.save()
    return

def make_save_csv(csv_content, filename, ext, username):
    files = Files.objects(owner=username)
    file_check = True
    for item in files:
        if item["name"] == filename:
            file_check=False
            item["type"] = ext
            item["csv"] = csv_content
            item.save()
            break
    if file_check:
        file_db = Files(owner=username, name=filename, type=ext, content="None", csv=csv_content)
        file_db.save()
    return


##############################################
################ Clean Log ###################
##############################################

def clean_log(log):
    try:
        log_file = open(log, "w")
        log_file.close()
        print ("Log file: " + log + " is clean")
        return
    except:
        print ("Cleaning log failed")
        return

##############################################
################ Get Files ###################
##############################################

def file_list(owner, files):
    build_list = list()
    jinja_list = list()
    csv_list =list()
    backup_list =list()
    for item in files:
        if item["type"] == "yaml":
            build_list.append(str(item["name"]))
        if item["type"] == "jinja":
            jinja_list.append(str(item["name"]))
        if item["type"] == "csv":
            csv_list.append(str(item["name"]))
        if item["type"] == "backup":
            backup_list.append(str(item["name"]))
    return build_list, jinja_list, csv_list, backup_list

##############################################
######### Make local Storage #################
##############################################

def make_storage(local_storage):
    if not os.path.exists(local_storage):
        os.makedirs(local_storage)
    return

##############################################
######## Do and Pull Queue Mgmt ##############
##############################################

def do_queue_check(payload_dict):
    queue_number = None
    try:
        username = payload_dict["username"]
        queue = Queues.objects(name=QUEUE_NAME).first()
        print("Do in use is: " + str(queue["do_in_use"]))
        if queue["do_in_use"] == True:
            if queue["do_current_user_one"] == "None":
                queue["do_in_use"] = True
                queue["do_current_user_one"] = username
                queue_number = 1
                print("Queue 1 choosen")
                queue.save()
                return queue_number
            elif queue["do_current_user_two"] == "None":
                queue["do_in_use"] = True
                queue["do_current_user_two"] = username
                queue_number = 2
                print("Queue 2 choosen")
                queue.save()
                return queue_number
            else:
                queue["do_user_queue"].append(username)
                queue.save()
                print("Placed " + username + " into the wait queue")
                wait = True
                time_elapsed = 0
                message = ("Another task is currently in process and yours has been queued\n\nIt will begin shortly and appreciate your patience\n")
                send_message(username, message)
                message = "Task " + payload_dict["job"] + "for " + username + " is in the wait queue."
                purpose = "support"
                send_message(username, message, purpose)
                while wait:
                    time.sleep(10)
                    time_elapsed += 10
                    print(username + " is waiting for a deployment. Been waiting: " + str(time_elapsed))
                    message = ('Task in queue. Waited so far ' + str(time_elapsed) + " seconds\n")
                    send_message(username, message)
                    queue = Queues.objects(name=QUEUE_NAME).first()
                    user = Users.objects(username=username).first()
                    check = user["process"]
                    if not check:
                        queue["do_user_queue"].remove(username)
                        queue.save()
                        message = 'Job cancelled'
                        send_message(username, message)
                        user["process"] = False
                        user.save()
                        return 'Received task', 200
                    elif time_elapsed == 900:
                        queue["do_user_queue"].remove(username)
                        queue.save()
                        message = '\nJob took to long please contact support\n'
                        send_message(username, message)
                        user["process"] = False
                        user.save()
                        return 'Received task', 200
                    elif username == queue["do_current_user_one"]:
                        wait = False
                        queue_number = 1
                    elif username == queue["do_current_user_two"]:
                        wait = False
                        queue_number = 2
                message = "Task " + payload_dict["job"] + "for " + username + " is out of queue in " + str(time_elapsed) + " seconds."
                purpose = "support"
                send_message(username, message, purpose)
                print("Queue " + str(queue_number) + " choosen")
                return queue_number
        else:
            queue["do_in_use"] = True
            queue["do_current_user_one"] = username
            queue_number = 1
            queue.save()
            print("Queue 1 choosen")
            return queue_number
    except Exception as e:
        print("Do queue failed to update")
        print(str(e))
        return queue_number

def do_queue_update(payload_dict):
    try:
        username = payload_dict["username"]
        queue_number = payload_dict["do_queue_number"]
        queue = Queues.objects(name=QUEUE_NAME).first()
        if queue_number == 1:
            if queue["do_user_queue"]:
                print("Users in queue")
                check_user = queue["do_user_queue"].pop(0)
                if check_user == username:
                    print("Queue has same current user so fixing it")
                    if queue["do_user_queue"]:
                        queue["do_current_user_one"] = queue["do_user_queue"].pop(0)
                        print("New user in queue so adding them")
                    else:
                        queue["do_current_user_one"] = "None"
                        print("No more users in the queue")
                else:
                    queue["do_current_user_one"] = check_user
            else:
                queue["do_current_user_one"] = "None"
        else:
            if queue["do_user_queue"]:
                print("Users in queue")
                check_user = queue["do_user_queue"].pop(0)
                if check_user == username:
                    print("Queue has same current user so fixing it")
                    if queue["do_user_queue"]:
                        queue["do_current_user_two"] = queue["do_user_queue"].pop(0)
                        print("New user in queue so adding them")
                    else:
                        queue["do_current_user_two"] = "None"
                        print("No more users in the queue")
                else:
                    queue["do_current_user_two"] = check_user
            else:
                queue["do_current_user_two"] = "None"

        if queue["do_current_user_one"] == "None" and queue["do_current_user_two"] == "None":
            queue["do_in_use"] = False
            print("Do queue in use is now False")
        queue.save()
    except Exception as e:
        print("Do queue failed to update")
        print(str(e))
    return

def pull_queue_check(payload_dict):
    queue_number = None
    try:
        username = payload_dict["username"]
        queue = Queues.objects(name=QUEUE_NAME).first()
        print("Pull in use is: " + str(queue["pull_in_use"]))
        if queue["pull_in_use"] == True:
            if queue["pull_current_user_one"] == "None":
                queue["pull_in_use"] = True
                queue["pull_current_user_one"] = username
                queue_number = 1
                print("Queue 1 choosen")
                queue.save()
                return queue_number
            elif queue["pull_current_user_two"] == "None":
                queue["pull_in_use"] = True
                queue["pull_current_user_two"] = username
                queue_number = 2
                print("Queue 2 choosen")
                queue.save()
                return queue_number
            else:
                queue["pull_user_queue"].append(username)
                queue.save()
                wait = True
                time_elapsed = 0
                message = ("Another task is currently in process and yours has been queued\n\nIt will begin shortly and appreciate your patience\n")
                send_message(username, message)
                message = "Task " + payload_dict["job"] + "for " + username + " is in the wait queue."
                purpose = "support"
                send_message(username, message, purpose)
                while wait:
                    time.sleep(10)
                    time_elapsed += 10
                    print(username + " is waiting for a deployment. Been waiting: " + str(time_elapsed))
                    message = ('Task in queue. Waited so far ' + str(time_elapsed) + " seconds\n")
                    send_message(username, message)
                    queue = Queues.objects(name=QUEUE_NAME).first()
                    user = Users.objects(username=username).first()
                    check = user["process"]
                    if not check:
                        queue["pull_user_queue"].remove(username)
                        queue.save()
                        message = 'Job cancelled'
                        send_message(username, message)
                        user["process"] = False
                        user.save()
                        return 'Received task', 200
                    elif time_elapsed == 900:
                        queue["pull_user_queue"].remove(username)
                        queue.save()
                        message = '\nJob took to long please contact support\n'
                        send_message(username, message)
                        user["process"] = False
                        user.save()
                        return 'Received task', 200
                    elif username == queue["pull_current_user_one"]:
                        wait = False
                        queue_number = 1
                    elif username == queue["pull_current_user_two"]:
                        wait = False
                        queue_number = 2
                message = "Task " + payload_dict["job"] + "for " + username + " is out of queue in " + str(time_elapsed) + " seconds."
                purpose = "support"
                send_message(username, message, purpose)
                print("Queue " + str(queue_number) + " choosen")
                return queue_number
        else:
            queue["pull_in_use"] = True
            queue["pull_current_user_one"] = username
            queue_number = 1
            queue.save()
            print("Queue 1 choosen")
            return queue_number
    except Exception as e:
        print("pull queue failed to update")
        print(str(e))
        return queue_number

def pull_queue_update(payload_dict):
    username = payload_dict["username"]
    queue_number = payload_dict["pull_queue_number"]
    queue = Queues.objects(name=QUEUE_NAME).first()
    if queue_number == 1:
        if queue["pull_user_queue"]:
            print("Users in queue")
            check_user = queue["pull_user_queue"].pop(0)
            if check_user == username:
                print("Queue has same current user so fixing it")
                if queue["pull_user_queue"]:
                    queue["pull_current_user_one"] = queue["pull_user_queue"].pop(0)
                    print("New user in queue so adding them")
                else:
                    queue["pull_current_user_one"] = "None"
                    print("No more users in the queue")
            else:
                queue["pull_current_user_one"] = check_user
        else:
            queue["pull_current_user_one"] = "None"
    else:
        if queue["pull_user_queue"]:
            print("Users in queue")
            check_user = queue["pull_user_queue"].pop(0)
            if check_user == username:
                print("Queue has same current user so fixing it")
                if queue["pull_user_queue"]:
                    queue["pull_current_user_two"] = queue["pull_user_queue"].pop(0)
                    print("New user in queue so adding them")
                else:
                    queue["pull_current_user_two"] = "None"
                    print("No more users in the queue")
            else:
                queue["pull_current_user_two"] = check_user
        else:
            queue["pull_current_user_two"] = "None"

    if queue["pull_current_user_one"] == "None" and queue["pull_current_user_two"] == "None":
        queue["pull_in_use"] = False
        print("Pull queue in use is now False")
    queue.save()
    
    try:
        pass
    except Exception as e:
        print("Pull queue failed to update")
        print(str(e))
    return

def broken_queue(payload_dict):
    print("Queues are broken")
    return

##############################################
############ Update Site Record ##############
##############################################

def getSite(username):
    user = Users.objects(username=username).first()
    token = user["auth"]
    try:
        site_names = []
        site_tags = []
        image_options = []
        machines = []
        domains = []
        publicwan = []
        privatewan = []
        element_list = []
        blank = []
        cgx_session = cloudgenix.API(controller=SDWAN_CONTROLLER, ssl_verify=SDWAN_SSL_VERIFY, update_check=False)
        cgx_session.interactive.use_token(token)
        site_id2n = {}
        if cgx_session.tenant_name:
            for site in cgx_session.get.sites().cgx_content["items"]:
                id = site['id']
                name = site['name']
                site_id2n[id] = name
                site_names.append(site['name'])
                tags = site['tags']
                if tags:
                    for tag in tags:
                        if tag not in site_tags:
                            site_tags.append(tag)
            for ipfix in cgx_session.get.ipfixprofiles().cgx_content["items"]:
                site_ipfix.append(ipfix['name'])
            for image in cgx_session.get.element_images().cgx_content["items"]:
                image_options.append(image['version'])
            for machine in cgx_session.get.machines().cgx_content["items"]:
                if machine["connected"]:
                    if machine["machine_state"] == "allocated":
                        machines.append(machine["sl_no"])
            for binding in cgx_session.get.servicebindingmaps().cgx_content["items"]:
                domains.append(binding["name"])
            for networks in cgx_session.get.wannetworks().cgx_content["items"]:
                if networks['type'] == 'publicwan':
                    publicwan.append(networks['name'])
                if networks['type'] == 'privatewan':
                    privatewan.append(networks['name'])
            for policy in cgx_session.get.securitypolicysets().cgx_content["items"]:
                security_policy.append(policy['name'])
            elements = {}
            for element in cgx_session.get.elements().cgx_content["items"]:
                elem_id = element['id']
                name = element['name']
                sid = element['site_id']
                if name:
                    try:
                        site_name = site_id2n[sid]
                        if site_name in elements.keys():
                            name_list = elements[site_name]
                            name_list.append(name)
                            name_list.sort()
                            elements[site_name] = name_list
                        else:
                            name_list = []
                            name_list.append(name)
                            elements[site_name] = name_list
                    except:
                        pass
            element_list.append(elements)
            image_options.sort(reverse=True)
            if Site.objects(username=username):
                site = Site.objects(username=username).first()
                site['site_names'] = site_names
                site['site_tags'] = site_tags
                site['csv_name'] = ""
                site['csv_site_names'] = blank
                site['make_file'] = ""
                site['make_csv'] = blank
                site['image_options'] = image_options
                site['machines'] = machines
                site['domains'] = domains
                site['publicwan'] = publicwan
                site['privatewan'] = privatewan
                site['elements'] = element_list
                site.save()
                print("User site object database updated")
            else:
                site = Site()
                site['username'] = username
                site['site_names'] = site_names
                site['site_tags'] = site_tags
                site['csv_name'] = ""
                site['csv_site_names'] = blank
                site['make_file'] = ""
                site['make_csv'] = blank
                site['image_options'] = image_options
                site['machines'] = machines
                site['domains'] = domains
                site['publicwan'] = publicwan
                site['privatewan'] = privatewan
                site['elements'] = element_list
                site.save()
                print("User site object database created")
        return
    except:
        print("Get Site Failed")
        if Site.objects(username=username):
            print("Already has a Site object")
        else:
            blank = []
            add = Site(username=username, site_names=blank, site_tags=blank, csv_name="", csv_site_names=blank, make_file="", make_csv=blank, image_options=blank, machines=blank, domains=blank, publicwan=blank, privatewan=blank, elements=blank)
            add.save()
        return

##############################################
########## Socket IO Tasks ###################
##############################################

@socketio.on('connect')
def connect():
    if current_user.is_anonymous:
        return False
    username = current_user.username
    room = username
    join_room(username)
    print('Client connected: ' + username)

@socketio.on('disconnect')
def disconnect():
    if current_user.is_anonymous:
        return False
    username = current_user.username
    room = username
    leave_room(username)
    print('Client disconnected')

@socketio.on('variable_change')
def variable_change(payload_dict, methods=['GET', 'POST']):
    if current_user.is_anonymous:
        return False
    username = current_user.username
    payload_dict["username"] = username
    make_change(payload_dict)
    print('Got variable for change')

@socketio.on('variable_undo')
def variable_undo(payload_dict, methods=['GET', 'POST']):
    if current_user.is_anonymous:
        return False
    username = current_user.username
    payload_dict["username"] = username
    undo_change(payload_dict)
    print('Got variable for undo change')

@socketio.on('view')
def variable(payload_dict, methods=['GET', 'POST']):
    if current_user.is_anonymous:
        return False
    username = current_user.username
    payload_dict["username"] = username
    view_config(payload_dict)
    print('Got variable for view')

def message_task_handler(username, message, purpose="message"):
    user = Users.objects(username=username).first()
    log = user["log"]
    if purpose == "message":
        log_file = open(log, "a")
        log_file.write(message + "\n")
        log_file.close()
        message = message.replace("Error", '<span class="red-warning">Error</span>')
        message = message.replace("cancelled", '<span class="red-warning">cancelled</span>')
        message = message.replace("failed", '<span class="red-warning">failed</span>')
        message = message.replace("Success..", '<span class="green-warning">Success..</span>')
        message = message.replace("Job complete", '<span class="green-warning">Job complete</span>')
        message = message.replace("correct version", '<span class="green-warning">correct version</span>')
        socketio.emit('newmessage', {'message': message}, to=username)
    elif purpose == "make":
        message = message.replace("{{", '<span class="green-warning">{{')
        message = message.replace("}}", '}}</span>')
        socketio.emit('newmessage', {'message': message}, to=username)
    elif purpose == "error":
        log_file = open(log, "a")
        log_file.write(message + "\n")
        log_file.close()
    else:
        log_file = open(log, "a")
        log_file.write(message + "\n")
        log_file.close()
    return

##############################################
############## Flask Logic  ##################
##############################################

@app.before_first_request
def set_session_timeout():
    print("Starting Flask - Automation v1.7")
    create_queue_db()
    create_admin_user()

@app.before_request
def set_session_timeout():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=240)
    session.modified = True

@login_manager.unauthorized_handler
def unauthorized_callback():
       return redirect('/login')

@login_manager.user_loader
def load_user(id):
    if id is None:
        redirect('/login')
    return Users.objects(id = id).first()

@app.route("/log_out", methods=["GET", "POST"])
@login_required
def logout():
    username = current_user.username
    user = Users.objects(username=username).first()
    user["process"]=False
    logout_user()
    return redirect('/login')

@app.route('/reset_queue', methods=['GET'])
@login_required
def reset_queue():
    try:
        update = Queues.objects(name=QUEUE_NAME).first()
        blank = []
        update["do_in_use"] = False
        update["do_current_user_one"] = "None"
        update["do_current_user_two"] = "None"
        update["do_user_queue"] = blank
        update["pull_in_use"] = False
        update["pull_current_user_one"] = "None"
        update["pull_current_user_two"] = "None"
        update["pull_user_queue"] = blank
        update.save()
        print("Updating queue database")
        return 'Queue Reset',200
    except:
        return 'Queue Reset Failed',200

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    username = current_user.username   
    message = None
    error = False 
    user_list = []
    for user in Users.objects():
        if user["username"] != ADMIN_USERNAME:
            user_list.append(user["username"])
    queue = Queues.objects(name=QUEUE_NAME).first()
    reg_status = queue["registration_lock"]
    if username != ADMIN_USERNAME:
        return redirect('/home')
    if request.method == 'POST':
        if 'reset' in request.form:
            if "selected_user" not in request.form:
                message = "Please select a user"
                error = True
                return render_template("admin.html", support=SUPPORT_EMAIL, error=error, message=message, user_list=user_list)
            selected_user = request.form["selected_user"]
            try:
                salt = "prisma"
                update = Users.objects(username=selected_user).first()
                password = ''.join(choice(ascii_uppercase) for i in range(8))
                db_password =  password + salt
                hash = hashlib.md5(db_password.encode())
                hash = hash.hexdigest()
                update["password"] = hash
                update.save()
                message = "Password has been reset to " + str(password)
            except:
                message = "Failed reseting password"
                error = True
        elif 'delete' in request.form:
            if "selected_user" not in request.form:
                message = "Please select a user"
                error = True
                return render_template("admin.html", support=SUPPORT_EMAIL, error=error, message=message, user_list=user_list)
            selected_user = request.form["selected_user"]
            try:
                user = Users.objects(username=selected_user).first()
                user.delete()
                try:
                    site = Site.objects(username=selected_user).first()
                    site.delete()
                except Exception as e:
                    print("Failed to clean up site")
                    print(str(e))
                try:
                    for item in Files.objects(owner=selected_user):
                        print(item["name"])
                        item.delete()
                except Exception as e:
                    print("Failed to clean up files")
                    print(str(e))
                message = selected_user + " has been deleted"
                user_list = []
                for user in Users.objects():
                    if user["username"] != ADMIN_USERNAME:
                        user_list.append(user["username"])
            except Exception as e:
                print(str(e))
                user_list = []
                for user in Users.objects():
                    if user["username"] != ADMIN_USERNAME:
                        user_list.append(user["username"])
                message = selected_user + " failed to delete"
                error = True
        elif 'lock' in request.form:
            try:
                update = Queues.objects(name=QUEUE_NAME).first()
                update["registration_lock"] = True
                reg_status = True
                update.save()
                message = "Registration locked"
            except:
                message = "Failed locking registration"
                error = True
        elif 'unlock' in request.form:
            try:
                update = Queues.objects(name=QUEUE_NAME).first()
                update["registration_lock"] = False
                reg_status = False
                update.save()
                message = "Registration unlocked"
            except:
                message = "Failed unlocking registration"
                error = True
    return render_template("admin.html", support=SUPPORT_EMAIL, error=error, message=message, user_list=user_list, reg_status=reg_status)
    

##############################################
############## Main Page Items ###############
##############################################

@app.route("/", methods=["GET"])
def default():
    return redirect('/landing')

@app.route("/landing", methods=["GET"])
def landing():
    if current_user.is_authenticated:
        return redirect('/home')
    return render_template('landing.html', support=SUPPORT_EMAIL)

@app.route("/disclaimer", methods=["GET", "POST"])
def disclaimer():
    return render_template('disclaimer.html', support=SUPPORT_EMAIL)
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        if 'forgot' in request.form:
            message = "Please contact " + SUPPORT_EMAIL + " for password reset support"
            return render_template("login.html", message=message)
    message = None
    salt = "prisma"
    if request.method == 'POST':
        if 'login' in request.form:
            if Users.objects(username= request.form['email']):
                user = Users.objects(username= request.form['email']).first()
                active = user["active"]
                if not active:
                    message = "Your account is currently disabled. Please contact support."
                    return render_template("login.html", message=message)
                db_password = request.form['password'] + salt
                hash = hashlib.md5(db_password.encode())
                hash = hash.hexdigest()
                user["password"]
                username = user["username"]
                if user["password"] == hash:
                    if login_user(user):
                        metric_update()
                        num = user["logins"]
                        user["logins"] = num + 1
                        user["last_login"] = datetime.now()
                        auth = user["auth"]
                        token_check, tenant = auth_check(auth)
                        user["auth_valid"] = token_check
                        user["tenant"] = tenant
                        user["process"] = False
                        log = user["log"]
                        user.save()
                        local_storage = user["local_storage"]
                        try:
                            shutil.rmtree(local_storage)
                        except:
                            pass
                        make_storage(local_storage)
                        clean_log(log)
                        print(username + " has logged in")
                        t1 = threading.Thread(target=getSite, args=(username,))
                        t1.start()
                        if username == ADMIN_USERNAME:
                            return redirect('/admin')
                        return redirect('/home')
                else:
                    message = 'Invalid Credentials. Please try again.'
            else:
                message = 'Invalid Credentials. Please try again.'
        else:
            return render_template("login.html", message=message)
    return render_template("login.html", message=message)

@app.route("/register", methods=["GET", "POST"])
def register():
    message = "Please provide registration information"
    salt = "prisma"
    if request.method == 'POST':
        queue = Queues.objects(name=QUEUE_NAME).first()
        if queue["registration_lock"] == True:
            message = 'Error: Registration is locked'
        elif Users.objects(username=request.form['email']):
            message = 'Error: User already exists'
        else:
            email_regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
            if(re.search(email_regex, request.form['email'])):
                if len(request.form['password']) >= 8:
                    if request.form['password'] == request.form['confirmpassword']:
                        username = request.form['email']
                        new_user = Users()
                        new_user["first"] = request.form['first']
                        new_user["last"] = request.form['last']
                        new_user["username"] = username
                        db_password = request.form['password'] + salt
                        hash = hashlib.md5(db_password.encode())
                        hash = hash.hexdigest()
                        new_user["password"] = hash
                        new_user["auth"] = "None"
                        new_user["register_date"] = datetime.now()
                        time = datetime.now()
                        internal = username.split('@')
                        internal_check = internal[1].strip()
                        new_user["active"] = True
                        new_user["last_login"] = datetime.now()
                        new_user["logins"] = 0
                        directory = request.form['email']
                        directory = directory.replace("@", "-")
                        directory = directory.replace(".com", "")
                        new_user["directory"] = directory
                        log = "/var/www/storage/" + directory + "/" + directory + "-log.txt"
                        local_storage = "/var/www/storage/" + directory + "/"
                        new_user["local_storage"] = local_storage
                        new_user["log"] = log
                        new_user["process"] = False
                        new_user["auth_valid"] = False
                        new_user["ip_address"] = "None"
                        new_user["custom_tools"] = ["None"]
                        custom_build = []
                        custom_build.append("Standard")
                        new_user["custom_build"] = custom_build
                        new_user.save()
                        message = "Your account is now active. Please login"                        
                    else:
                        message = 'Error: Passwords do not match'
                else:
                    message = 'Error: Password must be 8 characters'
            else:
                message = 'Error: Please enter a valid email address'
    return render_template("login.html", register=message, message=message)

@app.route("/home", methods=["GET", "POST"])
def home():
    print(SUPPORT_EMAIL)
    if current_user.is_authenticated:
         username = current_user.username
         user = Users.objects(username=username).first()
         if request.method == 'POST':
             if 'auth' in request.form:
                 user = Users.objects(username=username).first()
                 user["auth"] = request.form['auth-token']
                 auth = user["auth"]
                 user.save()
                 t1 = threading.Thread(target=getSite, args=(username,))
                 t1.start()
                 return redirect("/home")
         name = user["first"]
         auth = user["auth"]
         token_check, tenant = auth_check(auth)
         user["auth_valid"] = token_check
         user["tenant"] = tenant
         user.save()
         hidden_auth = "************" + auth[-6:]
         return render_template("home.html", support=SUPPORT_EMAIL, name=name, token_check=token_check, tenant=tenant, auth=hidden_auth)
    else:
         return render_template("landing.html", support=SUPPORT_EMAIL, )

@app.route("/token-help", methods=["GET", "POST"])
@login_required
def token_help():
    username = current_user.username
    user = Users.objects(username=username).first()
    if request.method == 'POST':
        if 'auth' in request.form:
            user = Users.objects(username=username).first()
            user["auth"] = request.form['auth-token']
            auth = user["auth"]
            user.save()
            return redirect("/token-help")
    name = user["first"]
    auth = user["auth"]
    token_check, tenant = auth_check(auth)
    user["auth_valid"] = token_check
    user["tenant"] = tenant
    user.save()
    hidden_auth = "************" + auth[-6:]
    return render_template("token-help.html", support=SUPPORT_EMAIL, name=name, token_check=token_check, tenant=tenant, auth=hidden_auth)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile(message=None, error=False):
    profile_message=None
    profile_error=False
    name = current_user.first + " " + current_user.last
    username = current_user.username
    user = Users.objects(username=username).first()
    if request.method == 'POST':
        if 'refresh' in request.form:
            user = Users.objects(username=username).first()
            t1 = threading.Thread(target=getSite, args=(username,))
            t1.start()
            profile_message = 'Refresh task has been sent'
        if 'password' in request.form:
            password = request.form['password']
            if len(password) >= 6:
                if password == request.form['confirmpassword']:
                    salt = "prisma"
                    db_password = password + salt
                    hash = hashlib.md5(db_password.encode())
                    hash = hash.hexdigest()
                    user["password"] = hash
                    profile_message = 'Password has been updated'
                else:
                    profile_error=True
                    profile_message = "Passwords don't match"
            else:
                profile_error=True
                profile_message = 'Password is to short'
    auth = user["auth"]
    token_check, tenant = auth_check(auth)
    user["auth_valid"] = token_check
    user["tenant"] = tenant
    user.save()
    file_list = Files.objects(owner=username)
    files = []
    for item in file_list:
        files.append(item["name"])
    hidden_auth = "************" + auth[-6:]
    return render_template("profile.html", support=SUPPORT_EMAIL, message=message, error=error, profile_message=profile_message, profile_error=profile_error, name=name, username=username, auth=hidden_auth, token_check=token_check, tenant=tenant, files=files)

@app.route("/profile_files", methods=["GET", "POST"])
@login_required
def profile_files():
    if request.method == 'GET':
        return redirect('/profile')
    username = current_user.username
    name = current_user.first + " " + current_user.last
    user = Users.objects(username=username).first()
    auth = user["auth"]
    token_check = user["auth_valid"]
    tenant = user["tenant"]
    if "selected_file" not in request.form:
        message = "Please choose a file"
        error = True
        return profile(message, error)
    filename = request.form["selected_file"]
    files = Files.objects(owner=username)
    build_list, jinja_list, csv_list, backup_list = file_list(username, files)
    if 'delete' in request.form:
        try:
            delete_file(username, filename)
        except:
            message = "File " + filename + " failed deleting"
            error = True
            return profile(message, error)
        message = "File " + filename + " has been deleted"
        error = False
        return profile(message, error)
    if 'download' in request.form:
        filepath = file_download(username, filename)
        head_tail = os.path.split(filepath)
        filename = head_tail[1]
        path = head_tail[0]
        return send_from_directory(directory=path, path=filename, as_attachment=True)  
    return redirect('/profile')

@app.route("/deploy", methods=["GET", "POST"])
@login_required
def deploy():
    username = current_user.username
    user = Users.objects(username=username).first()
    token_check = user["auth_valid"]
    tenant = user["tenant"]
    type="deploy"
    status = user["process"]
    sites = Site.objects(username=username).first()
    files = Files.objects(owner=username)
    build_list, jinja_list, csv_list, backup_list = file_list(username, files)
    message = None
    error = False
    view = True
    if request.method == 'POST':
        if 'upload' in request.form:
            file = request.files['file']
            if file.filename == '':
                message = "No file selected"
                error = True
                return render_template("deploy.html", support=SUPPORT_EMAIL, view=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)
            ext = os.path.splitext(file.filename)[-1].lower()
            if ext != '.yaml':
                message = "Please select a .yaml file"
                error = True
                return render_template("deploy.html", support=SUPPORT_EMAIL, view=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)
            filename = secure_filename(file.filename)
            ext = ext[1:]
            try:
                save_file(file, filename, ext, username)
            except:
                message = "File upload failed"
                return render_template("deploy.html", vsupport=SUPPORT_EMAIL, iew=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)
            files = Files.objects(owner=username)
            build_list, jinja_list, csv_list, backup_list = file_list(username, files)
            message = "File upload successful"
            return render_template("deploy.html", support=SUPPORT_EMAIL, view=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)
        if token_check == False:
            message = "Please update auth token"
            error = True
            return render_template("deploy.html", support=SUPPORT_EMAIL, view=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)
        if 'deploy' in request.form:
            if "build_list" not in request.form:
                message = "Please select a build file"
                error = True
                return render_template("deploy.html", support=SUPPORT_EMAIL, view=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)
            if status == True:
                error = True
                message = "Please wait till current job is done"
                return render_template("deploy.html", support=SUPPORT_EMAIL, view=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)
            if request.form["build_list"] == "":
                error = True
                message = "Please select a site file to deploy"
                return render_template("deploy.html", support=SUPPORT_EMAIL, view=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)
            filename = request.form["build_list"]
            filepath = file_download(username, filename)
            payload_dict = dict()            
            payload_dict["username"] = username
            payload_dict["job"] = type
            payload_dict["filepath"] = filepath
            t1 = threading.Thread(target=job_task_handler, args=(payload_dict,))
            t1.start()
            user["process"] = True
            user.save()
            message = "Task has been sent please wait..."
            view = False
        elif 'cancel' in request.form:
            user["process"] = False
            user.save()
        elif 'download' in request.form:
            filepath = user["log"]
            head_tail = os.path.split(filepath)
            filename = head_tail[1]
            path = head_tail[0]
            return send_from_directory(directory=path, path=filename, as_attachment=True)
    return render_template("deploy.html", support=SUPPORT_EMAIL, view=view, error=error, status=status, token_check=token_check, tenant=tenant, message=message, build_list=build_list)

@app.route("/make", methods=["GET", "POST"])
@login_required
def make():
    username = current_user.username
    user = Users.objects(username=username).first()
    token_check = user["auth_valid"]
    tenant = user["tenant"]
    type="make"
    status = user["process"]
    sites = Site.objects(username=username).first()
    site_list = sites["site_names"]
    message = None
    error = False
    make = "pull"
    download = False
    if request.method == 'POST':
        if token_check == False:
            message = "Please update auth token"
            error = True
            return render_template("make.html", support=SUPPORT_EMAIL, make=make, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
        if 'pull' in request.form:
            if status == True:
                error = True
                message = "Please wait till current job is done"
                return render_template("make.html", support=SUPPORT_EMAIL, make=make, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
            payload_dict = dict()
            payload_dict["username"] = username
            payload_dict["job"] = type
            payload_dict["site"] = request.form["site"]
            if "backup" in request.form:
                payload_dict["backup"] = True
            else:
                payload_dict["backup"] = False
            t1 = threading.Thread(target=job_task_handler, args=(payload_dict,))
            t1.start()
            user["process"] = True
            user.save()
            make = "make"
        elif 'save' in request.form:
            csv_name = request.form["csv"]
            jinja_name = request.form["jinja"]
            files = Files.objects(owner=username)
            site = Site.objects(username=username).first()
            file_content = site["make_file"]
            csv_content = site["make_csv"]
            try:
                filename = jinja_name + ".jinja"
                ext = "jinja"
                make_save_file(file_content, filename, ext, username)
                jinja_file = filename
            except Exception as e:
                print(str(e))
                message = "Jinja file save failed"
                error = True
                return render_template("make.html", support=SUPPORT_EMAIL, make=make, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
            try:
                filename = csv_name + ".csv"
                ext = "csv"
                make_save_csv(csv_content, filename, ext, username)
                csv_file = filename
            except Exception as e:
                print(str(e))
                message = "CSV file save failed"
                error = True
                return render_template("make.html", support=SUPPORT_EMAIL, make=make, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
            message = "Save completed but you can download them also here if you want."
            make = "download"
            return render_template("make.html", support=SUPPORT_EMAIL, csv_file=csv_file, jinja_file=jinja_file, make=make, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
        elif 'download' in request.form:
            filename = request.form["download"]
            filepath = file_download(username, filename)
            head_tail = os.path.split(filepath)
            filename = head_tail[1]
            path = head_tail[0]
            return send_from_directory(directory=path, path=filename, as_attachment=True)
    return render_template("make.html", support=SUPPORT_EMAIL, make=make, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)

@app.route("/update", methods=["GET", "POST"])
@login_required
def update():
    username = current_user.username
    user = Users.objects(username=username).first()
    type = "update"
    message = None
    error = False
    make = "pull"
    csv_name = ""
    jinja_name = ""
    download = False
    files = Files.objects(owner=username)
    build_list, jinja_list, csv_list, backup_list = file_list(username, files)
    if request.method == 'POST':
        if 'upload' in request.form:
            file = request.files['file']
            if file.filename == '':
                message = "No file selected"
                error = True
                return render_template("update.html", support=SUPPORT_EMAIL, make=make, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, csv_name=csv_name, jinja_name=jinja_name)
            ext = os.path.splitext(file.filename)[-1].lower()
            ext = ext[1:]
            if ext == 'jinja' or ext == 'csv':
                pass
            else:
                message = "Please select a jinja or csv file"
                error = True
                return render_template("update.html", support=SUPPORT_EMAIL, make=make, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, csv_name=csv_name, jinja_name=jinja_name)
            filename = secure_filename(file.filename)
            try:
                save_file(file, filename, ext, username)
            except:
                message = "File upload failed"
                return render_template("update.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)
            files = Files.objects(owner=username)
            build_list, jinja_list, csv_list, backup_list = file_list(username, files)
            message = "File upload successful"
        elif 'choose' in request.form:
            if request.form["csv_list"] == "" or request.form["jinja_list"] == "":
                message = "Please select a jinja or csv file"
                error = True
                return render_template("update.html", support=SUPPORT_EMAIL, make=make, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, csv_name=csv_name, jinja_name=jinja_name)
            payload_dict = dict()
            payload_dict["username"] = username
            payload_dict["job"] = type
            payload_dict["csv"] = request.form["csv_list"]
            base = request.form["csv_list"]
            csv_name = os.path.splitext(base)[0]
            payload_dict["jinja"] = request.form["jinja_list"]
            base = request.form["jinja_list"]
            jinja_name = os.path.splitext(base)[0]
            t1 = threading.Thread(target=job_task_handler, args=(payload_dict,))
            t1.start()
            make = "make"
        elif 'save' in request.form:
            site = Site.objects(username=username).first()
            csv_name = request.form["csv"]
            jinja_name = request.form["jinja"]
            files = Files.objects(owner=username)
            file_content = site["make_file"]
            csv_content = site["make_csv"]
            try:
                filename = jinja_name + ".jinja"
                ext = "jinja"
                make_save_file(file_content, filename, ext, username)
                jinja_file = filename
            except:
                message = "Jinja file save failed"
                error = True
                return render_template("update.html", support=SUPPORT_EMAIL, make=make, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
            try:
                filename = csv_name + ".csv"
                ext = "csv"
                make_save_csv(csv_content, filename, ext, username)
                csv_file = filename
            except:
                message = "CSV file save failed"
                error = True
                return render_template("update.html", support=SUPPORT_EMAIL, make=make, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
            message = "Save completed but you can download them also here if you want."
            make = "download"
            return render_template("update.html", support=SUPPORT_EMAIL, csv_file=csv_file, jinja_file=jinja_file, make=make, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, csv_name=csv_name, jinja_name=jinja_name)
        elif 'download' in request.form:
            filename = request.form["download"]
            filepath = file_download(username, filename)
            head_tail = os.path.split(filepath)
            filename = head_tail[1]
            path = head_tail[0]
            return send_from_directory(directory=path, path=filename, as_attachment=True)
    return render_template("update.html", support=SUPPORT_EMAIL, make=make, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, csv_name=csv_name, jinja_name=jinja_name)

@app.route("/build", methods=["GET", "POST"])
@login_required
def build():
    username = current_user.username
    user = Users.objects(username=username).first()
    token_check = user["auth_valid"]
    tenant = user["tenant"]
    type="build"
    status = user["process"]
    sites = Site.objects(username=username).first()
    files = Files.objects(owner=username)
    build_list, jinja_list, csv_list, backup_list = file_list(username, files)
    site_name = sites["csv_site_names"]
    custom_build = user["custom_build"]
    message = None
    error = False
    if request.method == 'POST':
        if 'upload' in request.form:
            file = request.files['file']
            if file.filename == '':
                message = "No file selected"
                error = True
                return render_template("build.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)
            ext = os.path.splitext(file.filename)[-1].lower()
            ext = ext[1:]
            if ext == 'jinja' or ext == 'csv':
                pass
            else:
                message = "Please select a jinja or csv file"
                error = True
                return render_template("build.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)
            filename = secure_filename(file.filename)
            try:
                save_file(file, filename, ext, username)
            except:
                message = "File upload failed"
                error = True
                return render_template("build.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)
            files = Files.objects(owner=username)
            build_list, jinja_list, csv_list, backup_list = file_list(username, files)
            message = "File upload successful"
            return render_template("build.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)
        elif 'choose' in request.form:
            if "csv_list" not in request.form:
                message = "Please first upload "
                error = True
                return render_template("build.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)
            choosen_csv = request.form["csv_list"]
            sites["csv_name"] = choosen_csv
            for item in files:
                if item["name"] == choosen_csv:
                    content = item["csv"]
            try:
                site_name = []
                site_name.append("All")
                for row in content:
                    site_name.append(row['site_name'])
                sites["csv_site_names"] = site_name
                sites.save()
                message = "CSV has been uploaded..."
            except:
                message = "File download failed"
                error = True
                return render_template("build.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)
        elif 'build' in request.form:
            if "site_list" not in request.form:
                message = "Please choose a CSV Database first"
                error = True
                return render_template("build.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)
            payload_dict = dict()
            payload_dict["username"] = username
            payload_dict["job"] = type
            payload_dict["csv"] = sites["csv_name"]
            payload_dict["site"] = request.form["site_list"]
            payload_dict["jinja"] = request.form["jinja_list"]
            payload_dict["custom"] = request.form["custom_list"]
            t1 = threading.Thread(target=build_site, args=(payload_dict,))
            t1.start()
            message = "Task has been sent please wait..."
        elif 'cancel' in request.form:
            user["process"] = False
            user.save()
        elif 'download' in request.form:
            filepath = user["log"]
            head_tail = os.path.split(filepath)
            filename = head_tail[1]
            path = head_tail[0]
            return send_from_directory(directory=path, path=filename, as_attachment=True)
    return render_template("build.html", support=SUPPORT_EMAIL, error=error, message=message, csv_list=csv_list, jinja_list=jinja_list, site_name=site_name, custom_build=custom_build)

@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    username = current_user.username
    user = Users.objects(username=username).first()
    token_check = user["auth_valid"]
    tenant = user["tenant"]
    type="delete"
    status = user["process"]
    sites = Site.objects(username=username).first()
    site_list = sites["site_names"]
    message = None
    error = False
    if request.method == 'POST':
        if token_check == False:
            message = "Please update auth token"
            error = True
            return render_template("delete.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
        if 'site' in request.form:
            if status == True:
                error = True
                message = "Please wait till current job is done"
                return render_template("delete.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)
            payload_dict = dict()
            payload_dict["username"] = username
            payload_dict["job"] = type
            payload_dict["site"] = request.form["site"]
            t1 = threading.Thread(target=job_task_handler, args=(payload_dict,))
            t1.start()            
            user["process"] = True
            user.save()
            message = "Task has been sent please wait..."
        elif 'cancel' in request.form:
            user["process"] = False
            user.save()
        elif 'download' in request.form:
            filepath = user["log"]
            head_tail = os.path.split(filepath)
            filename = head_tail[1]
            path = head_tail[0]
            return send_from_directory(directory=path, path=filename, as_attachment=True)
    return render_template("delete.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list)

@app.route("/backup", methods=["GET", "POST"])
@login_required
def backup():
    username = current_user.username
    user = Users.objects(username=username).first()
    token_check = user["auth_valid"]
    tenant = user["tenant"]
    type="backup"
    status = user["process"]
    sites = Site.objects(username=username).first()
    site_list = sites["site_names"]
    message = None
    error = False
    files = Files.objects(owner=username)
    build_list, jinja_list, csv_list, backup_list = file_list(username, files)
    if request.method == 'POST':
        if token_check == False:
            message = "Please update auth token"
            error = True
            return render_template("backup.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list, backup_list=backup_list)
        if 'backup' in request.form:
            if status == True:
                error = True
                message = "Please wait till current job is done"
                return render_template("backup.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list, backup_list=backup_list)
            payload_dict = dict()
            payload_dict["username"] = username
            payload_dict["job"] = type
            payload_dict["site"] = request.form["site"]
            t1 = threading.Thread(target=job_task_handler, args=(payload_dict,))
            t1.start()
            user["process"] = True
            user.save()
            message = "Task has been sent... When the job is complete please refresh to updated file list!"
        elif 'cancel' in request.form:
            user["process"] = False
            user.save()
        elif 'download' in request.form:
            filepath = user["log"]
            head_tail = os.path.split(filepath)
            filename = head_tail[1]
            path = head_tail[0]
            return send_from_directory(directory=path, path=filename, as_attachment=True)
        elif 'download_backup' in request.form:
            if request.form["files"] == "":
                message = "No file selected"
                error = True
                return render_template("backup.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list, backup_list=backup_list)
            file_selected = request.form["files"]
            for item in files:
                if item["name"] == file_selected:
                    filepath = item["location"]
                    break
                head_tail = os.path.split(filepath)
                file = head_tail[1]
                path = head_tail[0]
            return send_from_directory(directory=path, filename=file, as_attachment=True)
        elif 'delete' in request.form:
            if request.form["files"] == "":
                message = "No file selected"
                error = True
                return render_template("backup.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list, backup_list=backup_list)
            filename = request.form["files"]
            try:
                delete_file(username, filename)
            except:
                message = "File " + filename + " failed deleting"
                error = True
                return profile(message, error)
            message = "File " + filename + " has been deleted"
            error = False
    files = Files.objects(owner=username)
    build_list, jinja_list, csv_list, backup_list = file_list(username, files)
    return render_template("backup.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, site_list=site_list, backup_list=backup_list)

@app.route("/custom-tools", methods=["GET", "POST"])
@login_required
def custom_tools():
    username = current_user.username
    user = Users.objects(username=username).first()
    tools_list = user["custom_tools"]
    if request.method == 'POST':
        tool = request.form["tool"]
    return render_template("custom-tools.html", support=SUPPORT_EMAIL, tools_list=tools_list)
    
@app.route("/lqm-all-apps", methods=["GET", "POST"])
@login_required
def lqm_all_apps():
    username = current_user.username
    user = Users.objects(username=username).first()
    sites = Site.objects(username=username).first()
    site_list = sites["site_names"]
    token_check = user["auth_valid"]
    tenant = user["tenant"]
    status = user["process"]
    type = "lqm_all_apps"
    message = None
    error = False
    if request.method == 'POST':
        if token_check == False:
            message = "Please update auth token"
            error = True
            return render_template("lqm-all-apps.html", support=SUPPORT_EMAIL, error=error, message=message, status=status, token_check=token_check, tenant=tenant, site_list=site_list)
        if 'deploy' in request.form:
            if status == True:
                error = True
                message = "Please wait till current job is done"
            else:
                payload_dict = dict()
                if request.form["latency"] == "" or request.form["loss"] == "":
                    message = "Latency and loss can't be blank"
                    error = True
                    return render_template("lqm-all-apps.html", support=SUPPORT_EMAIL, error=error, message=message, status=status, token_check=token_check, tenant=tenant, site_list=site_list)
                try:
                    lqm_latency = None
                    lqm_latency = int(request.form["latency"])
                except:
                    print("Failed to enter an int latency")
                    message = "Please enter a number value for latency"
                    error = True
                    return render_template("lqm-all-apps.html", support=SUPPORT_EMAIL, error=error, message=message, status=status, token_check=token_check, tenant=tenant, site_list=site_list)
                try:
                    lqm_loss = None
                    lqm_loss = int(request.form["loss"])
                except:
                    try:
                        lqm_loss = None
                        lqm_loss = float(request.form["loss"])
                        loss_check = False
                    except:
                        message = "Please enter a number value for loss"
                        error = True
                        return render_template("lqm-all-apps.html", support=SUPPORT_EMAIL, error=error, message=message, status=status, token_check=token_check, tenant=tenant, site_list=site_list)
                payload_dict["username"] = username
                payload_dict["latency"] = request.form["latency"]
                payload_dict["loss"] = request.form["loss"]
                payload_dict["site"] = request.form["site"]
                payload_dict["destroy"] = False
                payload_dict["job"] = type
                t1 = threading.Thread(target=lqm_all_apps_task, args=(payload_dict,))
                t1.start()
                user["process"] = True
                user.save()
                message = "Task has been sent please wait..."
        elif 'delete' in request.form:
            if status == True:
                error = True
                message = "Please wait till current job is done"
            else:
                payload_dict = dict()
                payload_dict["username"] = username
                payload_dict["site"] = request.form["site"]
                payload_dict["destroy"] = True
                payload_dict["job"] = type
                t1 = threading.Thread(target=lqm_all_apps_task, args=(payload_dict, ))
                t1.start()
                user["process"] = True
                user.save()
                message = "Task has been sent please wait..."
        elif 'cancel' in request.form:
            user["process"] = False
            user.save()
        elif 'download' in request.form:
            filepath = user["log"]
            head_tail = os.path.split(filepath)
            filename = head_tail[1]
            path = head_tail[0]
            return send_from_directory(directory=path, path=filename, as_attachment=True)
    return render_template("lqm-all-apps.html", support=SUPPORT_EMAIL, error=error, message=message, status=status, token_check=token_check, tenant=tenant, site_list=site_list)

@app.route("/vpnmesh", methods=["GET", "POST"])
@login_required
def vpnmesh():
    username = current_user.username
    user = Users.objects(username=username).first()
    token_check = user["auth_valid"]
    tenant = user["tenant"]
    type="vpnmesh"
    status = user["process"]
    sites = Site.objects(username=username).first()
    domains = sites['domains']
    site_tags = sites['site_tags']
    publicwan = sites['publicwan']
    privatewan = sites['privatewan']
    message = None
    error = False
    if request.method == 'POST':
        if token_check == False:
            message = "Please update auth token"
            error = True
            return render_template("vpnmesh.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, domains=domains, site_tags=site_tags, publicwan=publicwan, privatewan=privatewan)
        if 'deploy' in request.form:
            if status == True:
                error = True
                message = "Please wait till current job is done"
                return render_template("vpnmesh.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, domains=domains, site_tags=site_tags, publicwan=publicwan, privatewan=privatewan)
            payload_dict = dict()
            if "onoffswitch" in request.form:
                if request.form["publicwan"] == '':
                    error = True
                    message = "Publicwan selection can't be blank"
                    return render_template("vpnmesh.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, domains=domains, site_tags=site_tags, publicwan=publicwan, privatewan=privatewan)
                payload_dict["publicvpn"] = True
            else:
                if request.form["privatewan"] == '':
                    error = True
                    message = "Private selection can't be blank"
                    return render_template("vpnmesh.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, domains=domains, site_tags=site_tags, publicwan=publicwan, privatewan=privatewan)
                payload_dict["publicvpn"] = False
            if "simulate" in request.form:
                payload_dict["simulate"] = True
            else:
                payload_dict["simulate"] = False
            payload_dict["username"] = username
            payload_dict["tag"] = request.form["tag"]
            payload_dict["domain"] = request.form["domain"]
            payload_dict["publicwan"] = request.form.getlist("publicwan")
            payload_dict["privatewan"] = request.form["privatewan"]
            payload_dict["job"] = type
            payload_dict["destroy"] = False
            t1 = threading.Thread(target=vpnmesh_task, args=(payload_dict,))
            t1.start()
            user["process"] = True
            user.save()
            message = "Task has been sent please wait..."
        elif 'delete' in request.form:
            if status == True:
                error = True
                message = "Please wait till current job is done"
                return render_template("vpnmesh.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, domains=domains, site_tags=site_tags, publicwan=publicwan, privatewan=privatewan)
            payload_dict = dict()
            if "onoffswitch" in request.form:
                if request.form["publicwan"] == '':
                    error = True
                    message = "Publicwan selection can't be blank"
                    return render_template("vpnmesh.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, domains=domains, site_tags=site_tags, publicwan=publicwan, privatewan=privatewan)
                payload_dict["publicvpn"] = True
            else:
                if request.form["privatewan"] == '':
                    error = True
                    message = "Private selection can't be blank"
                    return render_template("vpnmesh.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, domains=domains, site_tags=site_tags, publicwan=publicwan, privatewan=privatewan)
                payload_dict["publicvpn"] = False
            if "simulate" in request.form:
                payload_dict["simulate"] = True
            else:
                payload_dict["simulate"] = False
            payload_dict["username"] = username
            payload_dict["tag"] = request.form["tag"]
            payload_dict["domain"] = request.form["domain"]
            payload_dict["publicwan"] = request.form.getlist("publicwan")
            payload_dict["privatewan"] = request.form["privatewan"]
            payload_dict["job"] = type
            payload_dict["destroy"] = True
            vpnmesh_task
            t1 = threading.Thread(target=vpnmesh_task, args=(payload_dict, ))
            t1.start()
            user["process"] = True
            user.save()
            message = "Task has been sent please wait..."
        elif 'cancel' in request.form:
            user["process"] = False
            user.save()
        elif 'download' in request.form:
            filepath = user["log"]
            head_tail = os.path.split(filepath)
            filename = head_tail[1]
            path = head_tail[0]
            return send_from_directory(directory=path, path=filename, as_attachment=True)
    return render_template("vpnmesh.html", support=SUPPORT_EMAIL, error=error, status=status, token_check=token_check, tenant=tenant, message=message, domains=domains, site_tags=site_tags, publicwan=publicwan, privatewan=privatewan)

##############################################
##### job_task_handler for Do and Pull #######
##############################################

def job_task_handler(payload_dict):
    username = payload_dict["username"]
    if payload_dict["job"] == "update":
        metric_update_tasks(payload_dict)
        update_task(payload_dict)
        print("Recieved task for update from " + username)
        return
    elif payload_dict["job"] == "deploy":
        ####################################################
        do_queue_number = do_queue_check(payload_dict)
        if not do_queue_number:
            broken_queue(payload_dict)
            return
        ####################################################
        print("Recieved task for deploy from " + username)
        metric_update_tasks(payload_dict)
        payload_dict["do_queue_number"] = do_queue_number
        deploy_task(payload_dict)
        return
    elif payload_dict["job"] == "delete":
        ####################################################
        do_queue_number = do_queue_check(payload_dict)
        if not do_queue_number:
            broken_queue(payload_dict)
            return
        payload_dict["do_queue_number"] = do_queue_number
        ####################################################
        pull_queue_number = pull_queue_check(payload_dict)
        if not pull_queue_number:
            broken_queue(payload_dict)
            return
        payload_dict["pull_queue_number"] = pull_queue_number
        ####################################################
        print("Recieved task for delete from " + username)
        metric_update_tasks(payload_dict)
        delete_task(payload_dict)
        return
    elif payload_dict["job"] == "make" or payload_dict["job"] == "backup":
        ####################################################
        pull_queue_number = pull_queue_check(payload_dict)
        if not pull_queue_number:
            broken_queue(payload_dict)
            return
        payload_dict["pull_queue_number"] = pull_queue_number
        ####################################################
        if payload_dict["job"] == "make":
            print("Recieved task for make from " + username)
            metric_update_tasks(payload_dict)
            make_task(payload_dict)
            return
        else:
            print("Recieved task for backup from " + username)
            metric_update_tasks(payload_dict)
            backup_task(payload_dict)
            return
    print("Recieved task but no job setup for " + payload_dict["job"])
    return

##############################################
################ Build Site ##################
##############################################

def build_site(payload_dict):
    time.sleep(2)
    username = payload_dict["username"]
    user = Users.objects(username=username).first()
    token = user["auth"]
    message = ('Build process starting... \n')
    message_task_handler(username, message)
    try:
        files = Files.objects(owner=username)
        for item in files:
            if item["name"] == payload_dict["csv"]:
                content = item["csv"]
    except:
        user["process"] = False
        user.save()
        message = ('Download CSV file failed.')
        message_task_handler(username, message)
        return
    try:
        site_csv_dict = dict()
        parameter_dict = dict()
        site_selection = payload_dict["site"]
        site_build_list = list()
        for row in content:
            name = row['site_name']
            if site_selection != "All":
                if name == site_selection:
                    for column, value in row.items():
                        site_csv_dict.setdefault(column, []).append(value)
                    if payload_dict["custom"] == "Standard":
                        parameter_dict  = standard(site_csv_dict)
                        site_build_list.append(parameter_dict)
                        message = ('CSV import successful for ' + name + ' and now using standard build')
                    elif payload_dict["custom"] == "Custom_dhcp_static":
                        parameter_dict  = custom_dhcp_static(site_csv_dict)
                        site_build_list.append(parameter_dict)
                        message = ('CSV import successful for ' + name + ' and now using custom_dhcp_static build')
                    elif payload_dict["custom"] == "Sunbelt":
                        parameter_dict  = sunbelt(site_csv_dict)
                        site_build_list.append(parameter_dict)
                        message = ('CSV import successful for ' + name + ' and now using Sunbelt build')
                    elif payload_dict["custom"] == "Fabick":
                        parameter_dict  = fabick(site_csv_dict)
                        site_build_list.append(parameter_dict)
                        message = ('CSV import successful for ' + name + ' and now using fabick build')
                    elif payload_dict["custom"] == "Allegis_EMEA":
                        parameter_dict  = allegis_emea(site_csv_dict)
                        site_build_list.append(parameter_dict)
                        message = ('CSV import successful for ' + name + ' and now using Allegis EMEA build')
                    else:
                        message = ('Error: ' + payload_dict["custom"] + " does not exsist")
                    message_task_handler(username, message)
            else:
                site_csv_dict.clear()
                for column, value in row.items():
                    site_csv_dict.setdefault(column, []).append(value)
                if payload_dict["custom"] == "Standard":
                    parameter_dict  = standard(site_csv_dict)
                    site_build_list.append(parameter_dict)
                    message = ('CSV import successful for ' + name + ' and now using standard build')
                elif payload_dict["custom"] == "Custom_dhcp_static":
                    parameter_dict  = custom_dhcp_static(site_csv_dict)
                    site_build_list.append(parameter_dict)
                    message = ('CSV import successful for ' + name + ' and now using custom_dhcp_static build')
                elif payload_dict["custom"] == "Sunbelt":
                    parameter_dict  = sunbelt(site_csv_dict)
                    site_build_list.append(parameter_dict)
                    message = ('CSV import successful for ' + name + ' and now using Sunbelt build')
                elif payload_dict["custom"] == "Fabick":
                    parameter_dict  = fabick(site_csv_dict)
                    site_build_list.append(parameter_dict)
                    message = ('CSV import successful for ' + name + ' and now using fabick build')
                elif payload_dict["custom"] == "Allegis_EMEA":
                    parameter_dict  = allegis_emea(site_csv_dict)
                    site_build_list.append(parameter_dict)
                    message = ('CSV import successful for ' + name + ' and now using Allegis EMEA build')
                else:
                    message = ('Error: ' + payload_dict["custom"] + " does not exsist")
                message_task_handler(username, message)

    except:
        user["process"] = False
        user.save()
        time.sleep(1)
        message = ('Build process failed. Please check your CSV headers.')
        message_task_handler(username, message)
        return
    message = ("\nCreate Jinja2 environment...\n")
    message_task_handler(username, message)
    try:
        for site in site_build_list:
            parameter_dict = site
            jinja(payload_dict, parameter_dict)
    except:
        user["process"] = False
        user.save()
        message = ('Build process failed. Please check your CSV headers.')
        message_task_handler(username, message)
        return
    user["process"] = False
    user.save()
    message = ('\nJob complete\n')
    message_task_handler(username, message)
    return

def standard(site_csv_dict):
    parameter_dict = dict()
    for key,value in site_csv_dict.items():
        parameter_dict[key] = value[0]
    address_concat = ""
    if "street" in parameter_dict:
        address_concat = parameter_dict['street']
    if "city" in parameter_dict:
        address_concat += ", " + parameter_dict['city']
    if "state" in parameter_dict:
        address_concat += ", " + parameter_dict['state']
    if "post_code" in parameter_dict:
        address_concat += ", " + parameter_dict['post_code']
    if "country" in parameter_dict:
        address_concat += ", " + parameter_dict['country']
    if address_concat != "":
        address_concat = address_concat.strip()
        map_url = f"https://www.mapquestapi.com/geocoding/v1/address?key=ejebwfz7Ewm4eAkR9sxGMiCUccasfE6W&location={address_concat}"
        location = requests.get(url=map_url, verify=False).json()
        latLng = location['results'][0]['locations'][0]['latLng']
        parameter_dict["site_lat"] = latLng['lat']
        parameter_dict["site_long"] = latLng['lng']
    return parameter_dict

def jinja(payload_dict, parameter_dict):
    try:
        username = payload_dict["username"]
        user = Users.objects(username=username).first()
        files = Files.objects(owner=username)
        filename = payload_dict["jinja"]
        filepath = file_download(username, filename)
        head_tail = os.path.split(filepath)
        filename = head_tail[1]
        path = head_tail[0]
        
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath=path))
        template = env.get_template(filename)
        file_content = template.render(parameter_dict)
        filename = parameter_dict['site_name'] + ".yaml"
        ext = "yaml"
        make_save_file(file_content, filename, ext, username)
        time.sleep(1)
        message = ("Configuration created..." + (parameter_dict['site_name'] + ".yaml"))
        message_task_handler(username, message)
        return
    except Exception as e:
        message = ('Build process failed. Jinja conversion unsuccessful. Download log for details..')
        message_task_handler(username, message)
        purpose = ("error")
        message_task_handler(username, message, purpose)
        return

##############################################
################# Make Site ##################
##############################################

def make_task(payload_dict):
    time.sleep(2)
    username = payload_dict["username"]
    user = Users.objects(username=username).first()
    token = user["auth"]
    files = Files.objects(owner=username)
    site = payload_dict["site"]
    backup = payload_dict["backup"]
    temp = user["local_storage"]
    logfile = user["log"]
    pull_queue_number = payload_dict["pull_queue_number"]
    message = ("Starting make for " + site + "... \n")
    message_task_handler(username, message)
    try:
        if pull_queue_number == 1:
            go_pull_one(username, site, token, temp, logfile, socketio, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY)
        else:
            go_pull_two(username, site, token, temp, logfile, socketio, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY)
        filename = site + ".yaml"
        filepath = os.path.join(temp, filename)
        if backup:
            ext = "backup"
            save_backup(filepath, filename, ext, username)
        pull_queue_update(payload_dict)
    except Exception as e:
        user["process"] = False
        user.save()
        print(str(e))
        message = ('Pull failed')
        message_task_handler(username, message)
        pull_queue_update(payload_dict)
        return
    try:
        dict_csv = dict()
        file_temp = open(filepath, "r")
        intial_file = file_temp.readlines()
        line_start = 0
        line_serial_one = 0
        line_serial_two = 0
        line_cord = 0
        line_num = 0
        for line in intial_file:
            if "sites v" + SITE_API + ":" in line:
                line_start = line_num
                line_start += 1
            if "serial_number:" in line:
                if line_serial_one == 0:
                    line_serial_one = line_num
                else:
                    line_serial_two = line_num
            if "latitude:" in line:
                line_cord = line_num
            line_num += 1

        file_temp = open(filepath, "r")
        message = file_temp.read()

        get = intial_file[line_start]
        head_tail = get.split(": ")
        data = head_tail[0].strip()
        site_name = data.replace(":","")
        message = message.replace(site_name, "{{ site_name }}")
        dict_csv["site_name"] = site_name
        
        if line_serial_one != 0:
            get = intial_file[line_serial_one]
            head_tail = get.split(": ")
            ion_serial_number_1 = head_tail[1].strip()
            message = message.replace(ion_serial_number_1, "{{ ion_serial_number_1 }}")
            dict_csv["ion_serial_number_1"] = ion_serial_number_1

        if line_serial_two != 0:
            get = intial_file[line_serial_two]
            head_tail = get.split(": ")
            ion_serial_number_2 = head_tail[1].strip()
            message = message.replace(ion_serial_number_2, "{{ ion_serial_number_2 }}")
            dict_csv["ion_serial_number_2"] = ion_serial_number_2

        get = intial_file[line_cord]
        head_tail = get.split(": ")
        site_lat = head_tail[1].strip()
        if site_lat == "0.0":
            print("Site latitude is blank")
        else:
            message = message.replace(site_lat, "{{ site_lat }}")

        line_cord += 1
        get = intial_file[line_cord]
        head_tail = get.split(": ")
        site_long = head_tail[1].strip()
        if site_long == "0.0":
            print("Site longitude is blank")
        else:
            message = message.replace(site_long, "{{ site_long }}")

        line_start += 2
        get = intial_file[line_start]
        head_tail = get.split(": ")
        if len(head_tail) == 2:
            site_city = head_tail[1].strip()
            message = message.replace(site_city, "{{ city }}")
            dict_csv["city"] = site_city

        line_start += 1
        get = intial_file[line_start]
        head_tail = get.split(": ")
        if len(head_tail) == 2:
            site_country = head_tail[1].strip()
            message = message.replace(site_country, "{{ country }}")
            dict_csv["country"] = site_country

        line_start += 1
        get = intial_file[line_start]
        head_tail = get.split(": ")
        if len(head_tail) == 2:
            site_post_code = head_tail[1].strip()
            message = message.replace(site_post_code, "{{ post_code }}")
            dict_csv["post_code"] = site_post_code

        line_start += 1
        get = intial_file[line_start]
        head_tail = get.split(": ")
        if len(head_tail) == 2:
            site_state = head_tail[1].strip()
            message = message.replace(site_state, "{{ state }}")
            dict_csv["state"] = site_state

        line_start += 1
        get = intial_file[line_start]
        head_tail = get.split(": ")
        if len(head_tail) == 2:
            site_street = head_tail[1].strip()
            message = message.replace(site_street, "{{ street }}")
            dict_csv["street"] = site_street

        site = Site.objects(username=username).first()
        site["make_file"] = message
        dict_csv_list = []
        dict_csv_list.append(dict_csv)
        site["make_csv"] = dict_csv_list
        site.save()

        user["process"] = False
        user.save()
        purpose = "make"
        message_task_handler(username, message, purpose)
        try:
            os.remove(filepath)
        except:
            print("File is not local")
    except:
        user["process"] = False
        user.save()
        message = ('Jinja build failed')
        message_task_handler(username, message)
        return
    return

def undo_change(payload_dict):
    username = payload_dict["username"]
    site = Site.objects(username=username).first()
    message = site["make_file"]
    dict_csv = site["make_csv"][0]
    variable = payload_dict["data"]
    row = payload_dict["row"]
    all = payload_dict["all"]
    try:
        if "{{" not in variable:
            response = '<span class="red-warning">Error:</span> Please select the entire variable'
            socketio.emit('newvariable', {'message': response}, to=username)
        elif "}}" not in variable:
            response = '<span class="red-warning">Error:</span> Please select the entire variable'
            socketio.emit('newvariable', {'message': response}, to=username)
        elif all == "yes":
            count = message.count(variable)
            variable = variable.replace("{{ ", "")
            variable = variable.replace(" }}", "")
            data = dict_csv[variable]
            message = message.replace("{{ " + variable + " }}", data)
            del dict_csv[variable]
            site["make_file"] = message
            dict_csv_list = []
            dict_csv_list.append(dict_csv)
            site["make_csv"] = dict_csv_list
            site.save()
            response = '<span class="green-warning">Variable</span> has been removed from ' + str(count) + ' places'
            socketio.emit('newvariable', {'message': response}, to=username)
            message = message.replace("{{", '<span class="green-warning">{{')
            message = message.replace("}}", '}}</span>')
            socketio.emit('newmessage', {'message': message}, to=username)
        else:
            orignal_variable = variable
            row_num = int(row)
            row_num = row_num - 1
            variable = variable.replace("{{ ", "")
            variable = variable.replace(" }}", "")
            data = dict_csv[variable]
            jinja_list = message.splitlines()
            update = jinja_list[row_num]
            update = update.replace("{{ " + variable + " }}", data)
            jinja_list[row_num] = update
            separator = '\n'
            message = separator.join(jinja_list)
            if orignal_variable in message:
                print("Still a variable left")
            else:
                del dict_csv[variable]
                dict_csv_list = []
                dict_csv_list.append(dict_csv)
                site["make_csv"] = dict_csv_list
            site["make_file"] = message
            site.save()
            response = '<span class="green-warning">Variable</span> has been removed'
            socketio.emit('newvariable', {'message': response}, to=username)
            message = message.replace("{{", '<span class="green-warning">{{')
            message = message.replace("}}", '}}</span>')
            socketio.emit('newmessage', {'message': message}, to=username)
    except:
        response = '<span class="red-warning">Error: </span>' + variable + ' update failed'
        socketio.emit('newvariable', {'message': response}, to=username)
    return

def make_change(payload_dict):
    username = payload_dict["username"]
    site = Site.objects(username=username).first()
    message = site["make_file"]
    dict_csv = site["make_csv"][0]
    data = payload_dict["data"]
    variable = payload_dict["variable"]
    row = payload_dict["row"]
    all = payload_dict["all"]
    try:
        if "{" in variable:
            response = '<span class="red-warning">Error: </span>you do not have to include {{ }}'
            socketio.emit('newvariable', {'message': response}, to=username)
        elif "}" in variable:
            response = '<span class="red-warning">Error: </span>you do not have to include {{ }}'
            socketio.emit('newvariable', {'message': response}, to=username)
        elif " " in variable:
            response = '<span class="red-warning">Error: </span>please do not include spaces'
            socketio.emit('newvariable', {'message': response}, to=username)
        elif "-" in variable:
            response = '<span class="red-warning">Error: </span>please do not include dash - in your variables instead use underscores _'
            socketio.emit('newvariable', {'message': response}, to=username)
        elif variable in dict_csv.keys():
            response = '<span class="red-warning">Error: </span>' + variable + ' already used'
            socketio.emit('newvariable', {'message': response}, to=username)
        elif all == "yes":
            dict_csv[variable] = data
            count = message.count(data)
            message = message.replace(data, "{{ " + variable + " }}")
            site["make_file"] = message
            dict_csv_list = []
            dict_csv_list.append(dict_csv)
            site["make_csv"] = dict_csv_list
            site.save()
            response = '<span class="green-warning">Variable</span> has been updated for ' + str(count) + " instances of " + data
            socketio.emit('newvariable', {'message': response}, to=username)
            message = message.replace("{{", '<span class="green-warning">{{')
            message = message.replace("}}", '}}</span>')
            socketio.emit('newmessage', {'message': message}, to=username)
        else:
            dict_csv[variable] = data
            row_num = int(row)
            row_num = row_num - 1
            jinja_list = message.splitlines()
            update = jinja_list[row_num]
            update = update.replace(data, "{{ " + variable + " }}")
            jinja_list[row_num] = update
            separator = '\n'
            message = separator.join(jinja_list)
            site["make_file"] = message
            dict_csv_list = []
            dict_csv_list.append(dict_csv)
            site["make_csv"] = dict_csv_list
            site.save()
            response = '<span class="green-warning">Variable</span> has been updated for ' + data
            socketio.emit('newvariable', {'message': response}, to=username)
            message = message.replace("{{", '<span class="green-warning">{{')
            message = message.replace("}}", '}}</span>')
            socketio.emit('newmessage', {'message': message}, to=username)
    except:
        response = '<span class="red-warning">Error: </span>' + variable + ' update failed'
        socketio.emit('newvariable', {'message': response}, to=username)
    return

##############################################
############### Delete Site ##################
##############################################

def delete_task(payload_dict):
    time.sleep(2)
    username = payload_dict["username"]
    user = Users.objects(username=username).first()
    files = Files.objects(owner=username)
    token = user["auth"]
    logfile = user["log"]
    site = payload_dict["site"]
    temp = user["local_storage"]
    do_queue_number = payload_dict["do_queue_number"]
    pull_queue_number = payload_dict["pull_queue_number"]
    try:
        message = ("Backing up site configuration for " + site + "... \n")
        message_task_handler(username, message)
        if pull_queue_number == 1:
            go_pull_one(username, site, token, temp, logfile, socketio, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY)
        else:
            go_pull_two(username, site, token, temp, logfile, socketio, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY)
        filename = site + ".yaml"    
        filepath = os.path.join(temp, filename)
        ext = "backup"
        save_backup(filepath, filename, ext, username)
        message = ('Completed saving backup\n')
        message_task_handler(username, message)
        pull_queue_update(payload_dict)
    except Exception as e:
        user["process"] = False
        user.save()
        print(str(e))
        message = ('Pull failed')
        message_task_handler(username, message)
        do_queue_update(payload_dict)
        pull_queue_update(payload_dict)
        return
    destroy = True
    message = ("Starting to delete site " + site + "... \n")
    message_task_handler(username, message)
    try:
        if do_queue_number == 1:
            go_do_one(username, token, filepath, logfile, socketio, Users, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY, destroy)
        else:
            go_do_two(username, token, filepath, logfile, socketio, Users, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY, destroy)
        t1 = threading.Thread(target=getSite, args=(username,))
        t1.start()
    except:
        user["process"] = False
        user.save()
        message = ('Deleting site failed')
        message_task_handler(username, message)
        do_queue_update(payload_dict)
        return
    user["process"] = False
    user.save()
    message = ('\nJob complete\n')
    message_task_handler(username, message)
    do_queue_update(payload_dict)
    try:
        os.remove(filepath)
    except:
        print("File is not local")
    return

##############################################
############## Update Jinja ##################
##############################################

def update_task(payload_dict):
    time.sleep(2)
    username = payload_dict["username"]
    try:
        csv = payload_dict["csv"]
        jinja = payload_dict["jinja"]
        files = Files.objects(owner=username)
        for item in files:
            if item["name"] == jinja:
                jinja_content = item["content"]
            if item["name"] == csv:
                csv_content = item["csv"]
        site = Site.objects(username=username).first()
        site["make_file"] = jinja_content
        site["make_csv"] = csv_content
        site.save()
        purpose = "make"
        message = jinja_content
        message_task_handler(username, message, purpose)
        return
    except Exception as e:
        message = ('Error getting Jinja and CSV \n')
        message_task_handler(username, message)
        print(str(e))
        return
        
##############################################
############### Backup Site ##################
##############################################

def backup_task(payload_dict):
    time.sleep(2)
    username = payload_dict["username"]
    user = Users.objects(username=username).first()
    token = user["auth"]
    logfile = user["log"]
    site = payload_dict["site"]
    temp = user["local_storage"]
    pull_queue_number = payload_dict["pull_queue_number"]
    print("queue " + str(pull_queue_number))
    try:
        message = ("Starting to backup site " + site + "... \n")
        message_task_handler(username, message)
        if pull_queue_number == 1:
            go_pull_one(username, site, token, temp, logfile, socketio, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY)
        else:
            go_pull_two(username, site, token, temp, logfile, socketio, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY)
        filename = site + ".yaml"    
        filepath = os.path.join(temp, filename)
        ext = "backup"
        save_backup(filepath, filename, ext, username)
        message = ('Completed saving backup\n')
        message_task_handler(username, message)
    except Exception as e:
        user["process"] = False
        user.save()
        message = ('Error: Failed to save backup files')
        message_task_handler(username, message)
        pull_queue_update(payload_dict)
        #print(str(e))
        return
    user["process"] = False
    user.save()
    message = ('Job complete\n')
    message_task_handler(username, message)
    pull_queue_update(payload_dict)
    try:
        os.remove(filepath)
    except:
        print("File is not local")
    return

##############################################
########### View Config ######################
##############################################

def view_config(payload_dict):
    username = payload_dict["username"]
    user = Users.objects(username=username).first()
    try:
        site = payload_dict["site"]
        files = Files.objects(owner=username)
        for item in files:
            if item["name"] == site:
                message = item["content"]
        socketio.emit('viewconfig', {'message': message}, to=username)
        print("View socket sent")
    except:
        response = '<span class="red-warning">Error: </span> Pulling config failed'
        socketio.emit('viewconfig', {'message': response}, to=username)
    return

##############################################
########### Deploy Task ######################
##############################################

def deploy_task(payload_dict):
    time.sleep(2)
    print("Starting deployment")
    username = payload_dict["username"]
    filepath = payload_dict["filepath"]
    do_queue_number = payload_dict["do_queue_number"]
    user = Users.objects(username=username).first()
    token = user["auth"]
    logfile = user["log"]
    try:
        if do_queue_number == 1:
            go_do_one(username, token, filepath, logfile, socketio, Users, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY)  
        else:
            go_do_two(username, token, filepath, logfile, socketio, Users, SDWAN_CONTROLLER, SDWAN_SSL_VERIFY)
    except Exception as e:
        user["process"] = False
        user.save()
        message = ('Deployment failed. Please contact ' + SUPPORT_EMAIL + ' for help.')
        message_task_handler(username, message)
        print(username + " deployment failed")
        print(str(e))
        do_queue_update(payload_dict)
        return
    user["process"] = False
    user.save()
    message = ('Job complete\n')
    message_task_handler(username, message)
    print(username + " deployment finished")
    do_queue_update(payload_dict)
    t1 = threading.Thread(target=getSite, args=(username,))
    t1.start()
    return

##############################################
############# LQM ALL Apps ###################
##############################################

def lqm_all_apps_task(payload_dict):
    time.sleep(2)
    username = payload_dict["username"]
    user = Users.objects(username=username).first()
    token = user["auth"]
    site_name = payload_dict["site"]
    destroy = payload_dict["destroy"]
    check = user["process"]
    try:
        cgx_session = cloudgenix.API(controller=SDWAN_CONTROLLER, ssl_verify=SDWAN_SSL_VERIFY, update_check=False)
        cgx_session.interactive.use_token(token)
        if cgx_session.tenant_name:
            message = ('Controller Login Success.. Starting job \n')
            message_task_handler(username, message)
        else:
            user["process"] = False
            user.save()
            message = ('Controller Login failed')
            message_task_handler(username, message)
            return
    except Exception as e:
        user["process"] = False
        user.save()
        message = ('Controller Login failed')
        message_task_handler(username, message)
        return
    try:
        if destroy:
            if site_name == "All":
                message = ("Deleting LQM All-Apps for all sites\n")
                message_task_handler(username, message)
            else:
                message = ("Deleting LQM All-Apps on site " + site_name + "\n")
                message_task_handler(username, message)
            for site in cgx_session.get.sites().cgx_content["items"]:
                if not check:
                    message = 'Job cancelled'
                    message_task_handler(username, message)
                    user["process"] = False
                    user.save()
                    return
                else:
                    user = Users.objects(username=username).first()
                    check = user["process"]
                site_check = False
                if site_name == "All":
                    site_check = True
                elif site_name == site['name']:
                    site_check = True
                if site["element_cluster_role"] != "SPOKE":
                    site_check = False
                if site_check:
                    for element in cgx_session.get.elements().cgx_content["items"]:
                        if element["site_id"] == site["id"]:
                            for item in cgx_session.get.element_extensions(site_id = site["id"], element_id = element["id"]).cgx_content["items"]:
                                if item["name"] == "All-Apps":
                                    resp = cgx_session.delete.element_extensions(site_id = site["id"], element_id = element["id"], extension_id=item['id'])
                                    if not resp:
                                        message = ("Error deleting LQM All-Apps on site " + site['name'] + " ION " + element['name'] + '. Download log for details..')
                                        message_task_handler(username, message)
                                        message = str(jdout(resp))
                                        purpose = ("error")
                                        message_task_handler(username, message, purpose)
                                    else:
                                        message = ("Deleting LQM All-Apps on site " + site['name'] + " ION " + element['name'])
                                        message_task_handler(username, message)
        else:
            latency = payload_dict["latency"]
            loss = payload_dict["loss"]
            if site_name == "All":
                message = ("Creating/Updating LQM All-Apps for all sites to latency: " + latency + " and loss: " + loss + "%\n")
                message_task_handler(username, message)
            else:
                message = ("Creating/Updating LQM All-Apps on site " + site_name +  " to latency: " + latency + " and loss: " + loss + "%\n")
                message_task_handler(username, message)
            for site in cgx_session.get.sites().cgx_content["items"]:
                if not check:
                    message = 'Job cancelled'
                    message_task_handler(username, message)
                    user["process"] = False
                    user.save()
                    return
                else:
                    user = Users.objects(username=username).first()
                    check = user["process"]
                site_check = False
                if site_name == "All":
                    site_check = True
                elif site_name == site['name']:
                    site_check = True
                if site["element_cluster_role"] != "SPOKE":
                    site_check = False
                if site_check:
                    for element in cgx_session.get.elements().cgx_content["items"]:
                        if element["site_id"] == site["id"]:
                            create_lqm = True
                            for item in cgx_session.get.element_extensions(site_id = site["id"], element_id = element["id"]).cgx_content["items"]:
                                if item["name"] == "All-Apps":
                                    create_lqm = False
                                    update_lqm = False
                                    if item["conf"]['packet_loss'] != loss:
                                        item["conf"]['packet_loss'] = loss
                                        update_lqm = True
                                    if item["conf"]['latency'] != latency:
                                        item["conf"]['latency'] = latency
                                        update_lqm = True
                                    if update_lqm:
                                        resp = cgx_session.put.element_extensions(site_id = site["id"], element_id = element["id"], extension_id=item['id'], data=item)
                                        if not resp:
                                            message = ("Failed to update LQM All-Apps on site " + site['name'] + " ION " + element['name'] + '. Download log for details..')
                                            message_task_handler(username, message)
                                            message = str(jdout(resp))
                                            purpose = ("error")
                                            message_task_handler(username, message, purpose)
                                        else:
                                            message = ("Updating LQM All-Apps on site " + site['name'] + " ION " + element['name'])
                                            message_task_handler(username, message)
                                    else:
                                        message = ("LQM All-Apps already created on site " + site['name'] + " ION " + element['name'])
                                        message_task_handler(username, message)
                            if create_lqm:
                                data = {"name": "All-Apps", "namespace": "thresholds/lqm/app/all", "entity_id": None, "disabled": False, "conf": {"latency": latency, "latency_en": True, "jitter": "0", "jitter_en": False, "packet_loss": loss, "packet_loss_en": True}}
                                resp = cgx_session.post.element_extensions(site_id = site["id"], element_id = element["id"], data=data)
                                if not resp:
                                    message = ("Error creating LQM All-Apps on site " + site['name'] + " ION " + element['name'] + '. Download log for details..')
                                    message_task_handler(username, message)
                                    message = str(jdout(resp))
                                    purpose = ("error")
                                    message_task_handler(username, message, purpose)
                                else:
                                    message = ("Creating LQM All-Apps on site " + site['name'] + " ION " + element['name'])
                                    message_task_handler(username, message)
    except:
        message = ("Error running the LQM Apps job")
        message_task_handler(username, message)
    user["process"] = False
    user.save()
    message = ('\nJob complete\n')
    message_task_handler(username, message)
    return

##############################################
############ VPN Mesh Task ###################
##############################################

def vpnmesh_task(payload_dict):
    time.sleep(2)
    username = payload_dict["username"]
    user = Users.objects(username=username).first()
    check = user["process"]
    token = user["auth"]
    domain = payload_dict["domain"]
    tag = payload_dict["tag"]
    publicvpn = payload_dict["publicvpn"]
    publicwan = payload_dict["publicwan"]
    privatewan = payload_dict["privatewan"]
    simulate = payload_dict["simulate"]
    try:
        cgx_session = cloudgenix.API(controller=SDWAN_CONTROLLER, ssl_verify=SDWAN_SSL_VERIFY, update_check=False)
        cgx_session.interactive.use_token(token)
        if cgx_session.tenant_name:
            message = ('Controller Login Success.. Starting job \n')
            message_task_handler(username, message)
        else:
            user["process"] = False
            user.save()
            message = ('Controller Login failed')
            message_task_handler(username, message)
            return
    except:
        user["process"] = False
        user.save()
        message = ('Controller Login failed')
        message_task_handler(username, message)
        return
    try:
        network_id_list = []
        for networks in cgx_session.get.wannetworks().cgx_content["items"]:
            if publicvpn:
                if networks['type'] == 'publicwan':
                    if 'All Public' in publicwan:
                        network_id_list.append(networks['id'])
                    elif networks['name'] in publicwan:
                        network_id_list.append(networks['id'])
            else:
                if networks['type'] == 'privatewan':
                    if networks['name'] == privatewan:
                        network_id_list.append(networks['id'])


        domain_n2id = {}
        for binding in cgx_session.get.servicebindingmaps().cgx_content["items"]:
            name = binding["name"]
            id = binding["id"]
            domain_n2id[name] = id

        site_id2n = {}
        wan_id2n = {}
        vpn_list = []
        for site in cgx_session.get.sites().cgx_content["items"]:
            site_name =  site['name']
            site_id =  site['id']
            site_id2n[site_id] = site_name

            if domain != "All":
                domain_id = domain_n2id[domain]
                if site['service_binding'] == domain_id:
                    domain_check = True
                else:
                    domain_check = False
            else:
                domain_check = True

            if tag == 'All':
                tag_check = True
                if site["element_cluster_role"] != "SPOKE":
                    tag_check = False
            elif site['tags']:
                if tag in site['tags']:
                    tag_check = True
                    if site['element_cluster_role'] != 'SPOKE':
                        tag_check = False
                else:
                    tag_check = False
            else:
                tag_check = False

            if tag_check and domain_check:
                for wanint in cgx_session.get.waninterfaces(site_id=site_id).cgx_content["items"]:
                    wan_name =  wanint['name']
                    if wan_name == None:
                        wan_name = "Unknown Name"
                    wan_id =  wanint['id']
                    wan_id2n[wan_id] = wan_name
                    if wanint["network_id"] in network_id_list:
                        vpn_list.append({site_id: wan_id})
    except:
        user["process"] = False
        user.save()
        message = ('Site and network list failed')
        message_task_handler(username, message)
        return
    try:
        destroy = payload_dict["destroy"]
        list_length = len(vpn_list)
        num = 1
        if simulate:
            if list_length != 0:
                if destroy:
                    message = ('This is a simulation to show you which sites and circuits would be included in the deletion of the VPN mesh\n')
                else:
                    message = ('This is a simulation to show you which sites and circuits would be included in the creation of the VPN mesh\n')
                message_task_handler(username, message)
                for site in vpn_list:
                    for site, wan in site.items():
                        site = site_id2n[site]
                        circuit = wan_id2n[wan]
                        message = ('VPN mesh would include site: ' + site + " with circuit " + circuit)
                        message_task_handler(username, message)
        elif destroy:
            if list_length != 0:
                message = ('Your VPN list is ' + str(list_length) + ' sites & circuits long. Starting process now')
                message_task_handler(username, message)
                for site in vpn_list:
                    if not check:
                        message = 'Job cancelled'
                        message_task_handler(username, message)
                        user["process"] = False
                        user.save()
                        return
                    user = Users.objects(username=username).first()
                    check = user["process"]
                    message = ('\nVPN Process is ' + str(num) + ' round out of ' + str(list_length) + ' complete\n')
                    message_task_handler(username, message)
                    num += 1
                    for site, wan in site.items():
                        for site_check in vpn_list:
                            for site_check, wan_check in site_check.items():
                                if site != site_check:
                                    vpn_site_check = False
                                    data = {"type":"basenet","nodes":[site]}
                                    for results in cgx_session.post.topology(data).cgx_content["links"]:
                                        key = 'sub_type'
                                        if key in results.keys():
                                            source_node_id = results['source_node_id']
                                            target_node_id = results['target_node_id']
                                            source_wan_if_id = results['source_wan_if_id']
                                            target_wan_if_id = results['target_wan_if_id']
                                            if source_node_id == site and target_node_id == site_check:
                                                if source_wan_if_id == wan and target_wan_if_id == wan_check:
                                                    vpn_site_check = True
                                                    anynetlinks_id = results['path_id']
                                            if source_node_id == site_check and target_node_id == site:
                                                if source_wan_if_id == wan_check and target_wan_if_id == wan:
                                                    vpn_site_check = True
                                                    anynetlinks_id = results['path_id']
                                    if vpn_site_check:
                                        src_site = site_id2n[site]
                                        src_circuit = wan_id2n[wan]
                                        dst_site = site_id2n[site_check]
                                        dst_circuit = wan_id2n[wan_check]
                                        resp = cgx_session.delete.tenant_anynetlinks(anynetlinks_id)
                                        if not resp:
                                            message = ("Error deleting VPN site: " + src_site + " circuit: " + src_circuit + " to site: " + dst_site + " circuit: " + dst_circuit)
                                            message_task_handler(username, message)
                                            message = str(jdout(resp))
                                            purpose = ("error")
                                            message_task_handler(username, message, purpose)
                                        else:
                                            message = ("Deleting VPN site: " + src_site + " circuit: " + src_circuit + " to site: " + dst_site + " circuit: " + dst_circuit)
                                            message_task_handler(username, message)
        else:
            if list_length != 0:
                message = ('Your VPN list is ' + str(list_length) + ' sites & circuits long. Starting process now')
                message_task_handler(username, message)
                for site in vpn_list:
                    if not check:
                        message = 'Job cancelled'
                        message_task_handler(username, message)
                        user["process"] = False
                        user.save()
                        return
                    user = Users.objects(username=username).first()
                    check = user["process"]
                    message = ('\nVPN Process is ' + str(num) + ' round out of ' + str(list_length) + ' complete\n')
                    message_task_handler(username, message)
                    num += 1
                    for site, wan in site.items():
                        for site_check in vpn_list:
                            for site_check, wan_check in site_check.items():
                                if site != site_check:
                                    vpn_site_check = False
                                    data = {"type":"basenet","nodes":[site]}
                                    for results in cgx_session.post.topology(data).cgx_content["links"]:
                                        key = 'sub_type'
                                        if key in results.keys():
                                            source_node_id = results['source_node_id']
                                            target_node_id = results['target_node_id']
                                            source_wan_if_id = results['source_wan_if_id']
                                            target_wan_if_id = results['target_wan_if_id']
                                            if source_node_id == site and target_node_id == site_check:
                                                if source_wan_if_id == wan and target_wan_if_id == wan_check:
                                                    vpn_site_check = True
                                            if source_node_id == site_check and target_node_id == site:
                                                if source_wan_if_id == wan_check and target_wan_if_id == wan:
                                                    vpn_site_check = True
                                    if not vpn_site_check:
                                        src_site = site_id2n[site]
                                        src_circuit = wan_id2n[wan]
                                        dst_site = site_id2n[site_check]
                                        dst_circuit = wan_id2n[wan_check]
                                        data = {"name":None,"description":None,"tags":None,"ep1_site_id":site,"ep1_wan_if_id":wan,"ep2_site_id":site_check,"ep2_wan_if_id":wan_check,"admin_up":"true","forced":"true","type":None,"vpnlink_configuration":None}
                                        resp = cgx_session.post.tenant_anynetlinks(data)
                                        if not resp:
                                            message = ("Error creating VPN site: " + src_site + " circuit: " + src_circuit + " to site: " + dst_site + " circuit: " + dst_circuit)
                                            message_task_handler(username, message)
                                            message = str(jdout(resp))
                                            purpose = ("error")
                                            message_task_handler(username, message, purpose)
                                        else:
                                            message = ("Creating VPN site: " + src_site + " circuit: " + src_circuit + " to site: " + dst_site + " circuit: " + dst_circuit)
                                            message_task_handler(username, message)
    except Exception as e:
        user["process"] = False
        user.save()
        message = ('VPN process failed')
        message_task_handler(username, message)
        print(str(e))
        return
    user["process"] = False
    user.save()
    message = ('\nJob complete\n')
    message_task_handler(username, message)
    return

##############################################
################## Main ######################
##############################################

if __name__ == '__main__':
    ENVIRONMENT_DEBUG = os.environ.get("APP_DEBUG", True)
    ENVIRONMENT_PORT = os.environ.get("APP_PORT", 5000)
    app.run(host='0.0.0.0', port=ENVIRONMENT_PORT, debug=ENVIRONMENT_DEBUG)
