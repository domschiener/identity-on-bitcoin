# -*- coding: utf-8 -*-

import Tkinter as tk
from helpers import *

TITLE_FONT = ("Helvetica", 18, "bold")
CURR_ENTITY = None
priv_key = None


class SampleApp(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        for F in (StartPage, EnrollEntity, AuthenticateEntity):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartPage)

    def show_frame(self, c):
        frame = self.frames[c]
        frame.tkraise()


class StartPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Welcome to your Identity Manager", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        button1 = tk.Button(self, text="Enroll new Entity",
                            command=lambda: controller.show_frame(EnrollEntity))
        button2 = tk.Button(self, text="Authenticate existing Entity",
                            command=lambda: controller.show_frame(AuthenticateEntity))
        button1.pack(pady=30)
        button2.pack(pady=30)


###
### ENTITY MANAGEMENT PAGES (creating and managing identities and service providers)
###


class Authenticated(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller

        label = tk.Label(self, text="You are currentley logged in with Entity: " + CURR_ENTITY.name, font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        make_identity = tk.Button(self, text="Create new identity", command=self.newidentity)
        make_identity.pack(pady=30)

        identities = tk.Button(self, text="View all identities", command=self.display_identities)
        identities.pack(pady=30)

        serviceproviders = tk.Button(self, text="Manage Service Providers", command=self.sp_management)
        serviceproviders.pack(pady=30)

    def newidentity(self):
        frame = create_identity(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()

    def display_identities(self):
        frame = show_identities(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()

    def sp_management(self):
        frame = service_providers(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class show_identities(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller

        label = tk.Label(self, text="List of Identities", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        pprint(CURR_ENTITY.identities)

        box = tk.Text(self, width=80, height=15, relief='flat')
        scroll = tk.Scrollbar(self)
        scroll.pack(side='right')
        box.config(yscrollcommand=scroll.set)
        box.pack()

        if CURR_ENTITY.identities:
            for identity in CURR_ENTITY.identities:
                box.insert('current', identity)
                box.insert('end', "\n")

            goback = tk.Button(self, text="Go back", command=self.main_page)
            goback.pack(pady=30)                
        else:
            no_identity = tk.Label(self, text="No identities")
            no_identity.pack()

            goback = tk.Button(self, text="Go back", command=self.main_page)
            goback.pack(pady=30)

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class create_identity(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller

        label = tk.Label(self, text="Creating Identity", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        title = tk.Text(self, width=80, height=10, relief='flat')
        title.insert('end', "In order to successfully create your identity it needs to be placed in the Blockchain. Send at least 15000 Satoshi to: %s . This will take some 5 - 10 minutes, so please be patient. In the meantime you can name your identity and create some attributes." % CURR_ENTITY.pub_address)
        title.pack()

        title2 = tk.Label(self, text="Name your new identity")
        title2.pack()

        self.choose_name = tk.Entry(self)
        self.choose_name.pack()

        button = tk.Button(self, text="Submit", command=self.named)
        button.pack(pady=10)

        goback = tk.Button(self, text="Go back", command=self.main_page)
        goback.pack(pady=30)

    def named(self):
        self.name = self.choose_name.get()

        frame = create_attributes(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class create_attributes(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller
        self.name = controller.name

        label = tk.Label(self, text="Creating Attributes for Identity: " + controller.name, font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        self.attr = tk.Text(self, width=100, height=20, relief='flat')
        self.attr.insert('end', 'You can add any number of inputs here, the only requirement is for it to fit the right format. The attributes you are about to enter need to be in dictionary format, i.e. {"attr1":"value1","attr2":"value1"}. Do not add anything else and double check that you have entered it correctly and do not use the attributed "name". P.S. you have to delete this entire text. ')
        self.attr.pack()

        submit = tk.Button(self, text="Submit", command=self.submit_identity)
        submit.pack()

        goback = tk.Button(self, text="Go back", command=self.main_page)
        goback.pack(pady=30)


    def submit_identity(self):
        global CURR_ENTITY

        identity = self.attr.get("1.0",'end-1c')
        self.identity_obj = ast.literal_eval(identity)

        if type(self.identity_obj) != type({}):
            error = tk.Label(self, text="Wrong input")
            error.pack()
        else:
            self.identity_obj["name"] = self.name
            print "Your identity: "
            pprint(self.identity_obj)

            frame = EternifyIdentity(self.container, self)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.tkraise()

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class EternifyIdentity(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller
        self.identity_obj = controller.identity_obj

        title = tk.Label(self, text="Placing your Entity in the Blockchain ", font=TITLE_FONT)
        title.pack(side="top", fill="x", pady=10)

        descr = tk.Text(self, width=80, height=5, relief='flat')
        descr.insert('end', "It's time for the last step: Placing your Identity into the Blockchain. Make sure you sent at least 15000 Satoshi to %s . Press the button below in order to retry and put your identity in the Blockchain" % CURR_ENTITY.pub_address)
        descr.pack()

        retry = tk.Button(self, text="Place in Blockchain", command=self.attempt_eternification)
        retry.pack(pady=10)

        goback = tk.Button(self, text="Go to the start page", command=self.main_page)
        goback.pack(pady=10)

    def attempt_eternification(self):
        global CURR_ENTITY
        if sum(utxo['value'] for utxo in unspent(CURR_ENTITY.pub_address)) > 10000:
            new_objects = newidentity(CURR_ENTITY, self.identity_obj, unspent(CURR_ENTITY.pub_address), priv_key)
            CURR_ENTITY = new_objects[0]
            actual_identity = new_objects[1]
            print "\nIdentity successfully created and encrypted: "
            pprint(actual_identity)

            success = tk.Label(self, text="Identity successfully created!")
            success.pack()
        else:
            print "Not enough confirmations or funds yet"
            print "Current UTXO: " + unspent(CURR_ENTITY.pub_address)

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class service_providers(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller

        label = tk.Label(self, text="Service Provider Management", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        make_identity = tk.Button(self, text="Authorize new Service Provider", command=self.authorize_sp)
        make_identity.pack(pady=30)

        identities = tk.Button(self, text="View all Service Providers", command=self.show_serviceproviders)
        identities.pack(pady=30)

        serviceproviders = tk.Button(self, text="Generate access Token", command=self.sp_management)
        serviceproviders.pack(pady=30)

        goback = tk.Button(self, text="Go back", command=self.main_page)
        goback.pack(pady=30)

    def authorize_sp(self):
        frame = authorization_service(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()

    def show_serviceproviders(self):
        frame = show_SPs(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()

    def sp_management(self):
        if CURR_ENTITY.serviceproviders:
            frame = genaccesstoken(self.container, self)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.tkraise()
        else:
            print "You have not authorized a service provider yet"

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class authorization_service(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller   

        label = tk.Label(self, text="Authorizing new Service Provider", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        description = tk.Text(self, width=100, height=5, relief='flat')
        description.insert('end', "You are about to authroize a new Service Provider with which you can start exchanging your identities. You have ultimate controll over your identity and decide which information the service provider gets access to.")
        description.config(state='disabled')
        description.pack()

        title2 = tk.Label(self, text="Provide the Name of the Service Provider")
        title2.pack()

        self.provider_name = tk.Entry(self)
        self.provider_name.pack()

        label = tk.Label(self, text="Enter the file path or paste the Public Key provided by the Service Provider", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        self.pk = tk.Entry(self)
        self.pk.pack(pady=10)

        button = tk.Button(self, text="Authorize Access", command=self.authorize)
        button.pack(pady=10)

        goback = tk.Button(self, text="Go back", command=self.main_page)
        goback.pack(pady=30)

    def authorize(self):
        global CURR_ENTITY

        chosen_name = self.provider_name.get()
        chosen_path = self.pk.get()

        try:
            if os.path.isfile(chosen_path):
                sp_publickey = open(chosen_path, 'rb+').read()

                CURR_ENTITY = SP_authorize(CURR_ENTITY, chosen_name, sp_publickey)
            else:
                CURR_ENTITY = SP_authorize(CURR_ENTITY, chosen_name, chosen_path)
        except Exception:
            print "Something went wrong."

        success = tk.Label(self, text="Successfully authorized " + chosen_name)
        success.pack()

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class show_SPs(tk.Frame):
    #TO-DO: revoke access to SP
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller   

        label = tk.Label(self, text="Authorized Service Providers", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        if CURR_ENTITY.serviceproviders:
            for provider in CURR_ENTITY.serviceproviders:
                for name in provider:
                    label = tk.Label(self, text=name)
                    label.pack()

            goback = tk.Button(self, text="Go back", command=self.main_page)
            goback.pack(pady=30)                
        else:
            no_sp = tk.Label(self, text="No Service Providers")
            no_sp.pack()

            goback = tk.Button(self, text="Go back", command=self.main_page)
            goback.pack(pady=30)

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class genaccesstoken(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller 

        providers = self.list_providers()
        identities = self.list_identities()

        label = tk.Label(self, text="Provide Access to Service Provider", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        title = tk.Label(self, text="Choose the service provider you would like to provide access")
        title.pack(pady=10)

        self.provider = tk.StringVar(self)
        menu = tk.OptionMenu(self, self.provider, *providers)
        menu.pack()

        title1 = tk.Label(self, text="Choose the identity you would like to identify with")
        title1.pack(pady=10)

        self.identity = tk.StringVar(self)
        menu2 = tk.OptionMenu(self, self.identity, *identities)
        menu2.pack(pady=10)

        submit = tk.Button(self, text="Next Step", command=self.nextstep)
        submit.pack(pady=10)

        goback = tk.Button(self, text="Go back", command=self.main_page)
        goback.pack(pady=10)


    def list_providers(self):
        providers = []
        for provider in CURR_ENTITY.serviceproviders:
            for name in provider:
                providers.append(name)

        return providers

    def list_identities(self):
        identities = []
        for identity in CURR_ENTITY.identities:
            identities.append(identity['name'])

        return identities

    def nextstep(self):
        chosen_provider = self.provider.get()
        chosen_identity = self.identity.get()

        self.provider_fingerprint = None
        self.identity_obj = None

        for provider in CURR_ENTITY.serviceproviders:
            for name in provider:
                if chosen_provider == name:
                    self.provider_fingerprint = provider[name]
                    break

        for identity in CURR_ENTITY.identities:
            if chosen_identity == identity['name']:
                self.identity_obj = identity
                print self.identity_obj
                break

        title2 = tk.Label(self, text="Which information would you like to decrypt?")
        title2.pack()

        self.decision = []

        for data in self.identity_obj:
            if data != 'name' and data != 'tx_id':
                var = tk.IntVar()
                option = tk.Checkbutton(self, text=data, variable=var)
                option.pack(pady=10)
                self.decision.append({data:var})

        submit = tk.Button(self, text="Next Step", command=self.finalstep)
        submit.pack(pady=10)

    def finalstep(self):
        decrypted_identity = {}
        decrypted_identity["name"] = self.identity_obj["name"]
        decrypted_identity["tx_id"] = self.identity_obj["tx_id"]

        for decision in self.decision:
            for key in decision:
                if decision[key].get() == 1:
                    decrypted_value = decrypt_attributes(self.identity_obj[key], priv_key)
                    decrypted_identity[key] = decrypted_value


        print self.provider_fingerprint
        self.encrypted_message = accesstoken(self.provider_fingerprint,str(decrypted_identity))
        print "Provide this access token to the service provider"
        print self.encrypted_message

        title2 = tk.Label(self, text="Successfully generated. Check Terminal for Token")
        title2.pack()

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class displaytoken(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller 

        label = tk.Label(self, text="Generated Access Token", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        title = tk.Label(self, text="Provide this access token to the service provider")
        title.pack(side="top", fill="x", pady=10)

        description = tk.Text(self, width=80, height=10, relief='flat')
        description.insert('end', controller.encrypted_message)
        description.pack()   

        goback = tk.Button(self, text="Go back", command=self.main_page)
        goback.pack(pady=10)

    def main_page(self):
        frame = Authenticated(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


###
### ENTITY PAGES (for enrolling)
###


class EnrollEntity(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller
        label = tk.Label(self, text="Enrolling New Entity", font=TITLE_FONT)
        intro = tk.Label(self, text="An entity represents your entirety, therefore it is the meta-object of you and all of your identities.", wraplength=400) 
        label.pack(side="top", fill="x", pady=10)
        intro.pack(pady=10)

        title = tk.Label(self, text="Entity Name")
        title.pack()
        self.ename = tk.Entry(self)
        self.ename.pack()

        button = tk.Button(self, text="Submit", command=self.get_entry)
        button.pack()

        button = tk.Button(self, text="Go to the start page", command=lambda: controller.show_frame(StartPage))
        button.pack()

    def get_entry(self):
        self.name = self.ename.get()
        self.ename.delete(0, 'end')

        print "Creating entity: " + self.name

        frame = EnrollEntity_AuthMethod(self.container, self)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()


class EnrollEntity_AuthMethod(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller.pageback
        self.name = controller.name

        title = tk.Label(self, text="The name of your entity: " + self.name, font=TITLE_FONT)
        title.pack(side="top", fill="x", pady=10)

        description = tk.Label(self, text="Now it's time to choose your authentication method. You can either choose a Password (oldskool), a private image or your fingerprint", anchor='w', justify='left', wraplength=400)
        description.pack()

        descr = tk.Label(self, text="Choose your desired Authentication Method")
        descr.pack(pady=10)

        self.option = tk.StringVar(self)
        menu = tk.OptionMenu(self, self.option, "Password", "Image/File", "Fingerprint")
        menu.pack(pady=10)

        title2 = tk.Label(self, text="Either enter your secret password or the file path")
        title2.pack()

        self.secret = tk.Entry(self)
        self.secret.pack()

        button = tk.Button(self, text="Submit", command=self.auth_choice)
        button.pack(pady=10)

        goback = tk.Button(self, text="Go to the start page", command=lambda: controller.pageback.show_frame(StartPage))
        goback.pack(pady=10)

    def auth_choice(self):
        self.method = self.option.get()
        choice = self.secret.get()
        self.secret.delete(0, 'end')

        global priv_key

        if self.method == 'Password':
            priv_key = generate_privkey(choice)
            self.generate()
        elif self.method == 'Image/File':
            if os.path.isfile(choice):
                priv_key = generate_privkey(open(choice,'rb+').read())
                self.generate()
            else:
                wrong_path =  tk.Label(self, text="Wrong file path. Please provide the correct and full path to your desired image", wraplength=400)
                wrong_path.pack()
        else:
            if os.path.isfile("./fingerprint.bmp"):
                priv_key = generate_privkey(open("./fingerprint.bmp",'rb+').read())
                self.generate()


    def generate(self):
        self.pub_key = privtopub(priv_key)
        self.pub_addr = pubtoaddr(self.pub_key)

        list_entities = get_entities()

        for entity in list_entities[::-1]:
            if entity.pub_key == self.pub_key:
                raise LookupError('Entity already exists')
        else:
            print "\nCreated your Bitcoin Identity"
            print "Your public key: " + self.pub_key
            print "Your public address: " + self.pub_addr
            print
            print "Proceed to the next step to finish process.\n"

            frame = EnrollEntity_Gen(self.container, self)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.tkraise()


class EnrollEntity_Gen(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller.pageback

        global CURR_ENTITY
        global priv_key

        self.name = controller.name
        self.pub_key = controller.pub_key
        self.pub_addr = controller.pub_addr
        self.auth_method = controller.method
        
        CURR_ENTITY = entity(self.name, self.pub_key, self.pub_addr, self.auth_method) 

        #generating GPG pair
        CURR_ENTITY.gen_gpg(priv_key)
        print "Generated your Public GPG Key"
        print CURR_ENTITY.gpg_pub

        title = tk.Label(self, text="Create your signature for " + self.name, font=TITLE_FONT)
        title.pack(side="top", fill="x", pady=10)


        title = tk.Text(self, width=80, height=8, relief='flat')
        title.insert('end', "Your entity was successfully generated. To finish the process, please send at least 15000 satoshi to: %s . This will take some 5 - 10 minutes, so please be patient In the meantime lets generate a signature for you to sign and have an additional proof of ownership. Enter a message you would like to sign to proof ownership (do not just write 'I own this', make it authentic)" % self.pub_addr)
        title.pack()

        self.message_sig = tk.Entry(self)
        self.message_sig.pack()

        button = tk.Button(self, text="Sign message", command=self.sign_message)
        button.pack()   

        goback = tk.Button(self, text="Go to the start page", command=lambda: controller.pageback.show_frame(StartPage))
        goback.pack()   

    def sign_message(self):
        global CURR_ENTITY
        self.message = self.message_sig.get()
        signed = CURR_ENTITY.gen_sig(self.message, priv_key)
        print "\nGenerated your signature: "
        print signed

        if signed:
            frame = EnrollEntity_Gen2(self.container, self)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.tkraise()
        else:
            print "Wrong signature"


class EnrollEntity_Gen2(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller

        title = tk.Label(self, text="Placing your Entity in the Blockchain ", font=TITLE_FONT)
        title.pack(side="top", fill="x", pady=10)

        descr = tk.Text(self, width=80, height=5, relief='flat')
        descr.insert('end', "It's time for the last step: Placing your Entity into the Blockchain. Make sure you sent at least 15000 Satoshi to %s . Press the button below in order to retry and put your entity in the Blockchain" % controller.pub_addr)
        descr.pack()

        retry = tk.Button(self, text="Place in Blockchain", command=self.attempt_eternification)
        retry.pack(pady=10)

        goback = tk.Button(self, text="Go to the start page", command=lambda: controller.pageback.show_frame(StartPage))
        goback.pack(pady=10)

    def attempt_eternification(self):
        global CURR_ENTITY

        if unspent(CURR_ENTITY.pub_address):
            if unspent(CURR_ENTITY.pub_address)[0]['value'] >= 10000:
                print "\nPlacing your entity in the Blockchain. This might take a while."
                CURR_ENTITY.eternify(unspent(CURR_ENTITY.pub_address), priv_key)

                title = tk.Label(self, text="Successfully placed your entity in the Blockchain. You can go back now")
                title.pack(pady=10)
            else:
                print "Not enough funds"
        else:
            print "Not enough confirmations yet"


class AuthenticateEntity(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.container = parent
        self.pageback = controller

        label = tk.Label(self, text="Authenticating existing Entity", font=TITLE_FONT)
        label.pack(side="top", fill="x", pady=10)

        title = tk.Label(self, text="Choose your Authentication Method")
        title.pack(side="top",  pady=10)

        self.auth_method = tk.StringVar(self)
        menu = tk.OptionMenu(self, self.auth_method,"Password", "Image/File", "Fingerprint")
        menu.pack(pady=10)

        description = tk.Label(self, text="Either enter the password or the image path for your Entity below. Make sure that the Entity already exists.", wraplength=400)
        description.pack(side="top",  pady=10)

        self.auth_secret = tk.Entry(self)
        self.auth_secret.pack()

        button = tk.Button(self, text="Authenticate", command=self.authenticate_entity)
        button.pack(pady=10)   

        goback = tk.Button(self, text="Go to the start page", command=lambda: controller.pageback.show_frame(StartPage))
        goback.pack(pady=10)

    def authenticate_entity(self):
        global CURR_ENTITY
        global priv_key

        chosen_method = self.auth_method.get()
        chosen_secret = self.auth_secret.get()

        if chosen_method == 'Password':
            authenticated_entity = authenticate(chosen_secret)
            CURR_ENTITY = authenticated_entity[0]
            priv_key = authenticated_entity[1]

            frame = Authenticated(self.container, self)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.tkraise()

        elif chosen_method == 'Image/File':
            if os.path.isfile(chosen_secret):
                authenticated_entity = authenticate(open(chosen_secret,'rb+').read())
                CURR_ENTITY = authenticated_entity[0]
                priv_key = authenticated_entity[1]
                print "Successfully authenticated Entity '%s', with pub_key %s\n" % (CURR_ENTITY.name, CURR_ENTITY.pub_key)
                frame = Authenticated(self.container, self)
                frame.grid(row=0, column=0, sticky="nsew")
                frame.tkraise()
            else:
                wrong_path =  tk.Label(self, text="Wrong file path. Please provide the correct and full path to your desired image", wraplength=400)
                wrong_path.pack()
        else:
            chosen_secret = "./fingerprint.bmp"

            if os.path.isfile(chosen_secret):
                authenticated_entity = authenticate(open(chosen_secret,'rb+').read())
                CURR_ENTITY = authenticated_entity[0]
                priv_key = authenticated_entity[1]
                print "Successfully authenticated Entity '%s', with pub_key %s\n" % (CURR_ENTITY.name, CURR_ENTITY.pub_key)
                frame = Authenticated(self.container, self)
                frame.grid(row=0, column=0, sticky="nsew")
                frame.tkraise()
            else:
                print "Failure"



if __name__ == "__main__":
    app = SampleApp()
    app.maxsize(700, 700)
    app.mainloop()