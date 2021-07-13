from tkinter import messagebox
from datetime import datetime
from firebase import firebase
from tkinter import ttk     
from tkinter import *
import PIL.ImageTk
import webbrowser
import PIL.Image
import shutil
import sys
import re
import os


class FileOrganizer:
    def __init__(self):
        self.screen = Tk()

        self.userDatabase = firebase.FirebaseApplication("https://filemanager-2febc-default-rtdb.firebaseio.com/", None)

        self.screenWidth = self.screen.winfo_screenwidth()
        self.screenHeight = self.screen.winfo_screenheight()

        self.screen.geometry(f"{self.screenWidth}x{self.screenHeight}")
        self.screen.title("File Organizer")
        self.screen.resizable(False, False)
        self.screen.protocol("WM_DELETE_WINDOW", self.closeScreen)
        self.screen.iconbitmap("@icon.xbm")
        # self.screen.attributes('-alpha', 0.8)

        self.extensions_dictionary = {}

        self.GotExtensionsDictionary = self.userDatabase.get("/filemanager-2febc-default-rtdb:/", None)
        self.GotExtensionsDictionaryKey = list(self.GotExtensionsDictionary.keys())[0]
        self.extensions_dictionary.update(self.GotExtensionsDictionary[self.GotExtensionsDictionaryKey])
        
        self.getDatabaseKeyValues = self.userDatabase.get("/filemanager-2febc-default-rtdb:/", None)
        self.getDatabaseKey_0 = list(self.getDatabaseKeyValues.keys())[0]
        
        self.addedExtensions = []
        self.updatedExtensions = []

        # self.regexUsername = r"^[A-Za-z]\\w{5, 29}$"
        # self.regexPassword = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
        
        self.regexUsername = "."
        self.regexPassword = "."
        
        self.patternUsername = re.compile(self.regexUsername)
        self.patternPassword = re.compile(self.regexPassword)

        self.username_1 = StringVar()
        self.password_1 = StringVar()
        self.isChecked_1 = BooleanVar()

        self.username_2 = StringVar()
        self.password_2 = StringVar()

        self.selectedQuestion_1 = StringVar()
        self.selectedQuestionAnswer_1 = StringVar()

        self.username_3 = StringVar()
        self.selectedQuestion_2 = StringVar()
        self.selectedQuestionAnswer_2 = StringVar()

        self.folderPath_1 = StringVar()

        self.oldPassword_1 = StringVar()
        self.newPassword_1 = StringVar()
        self.confirmPassword_1 = StringVar()

        self.selectUser = IntVar()

        self.adminCheckVar_1 = BooleanVar()
        self.statusCheckVar_1 = BooleanVar()
        
        self.extensionKey_1 = StringVar()
        self.extensionValue_1 = StringVar()
        
        self.extensionKey_2 = StringVar()
        self.extensionValue_2 = StringVar()

        self.setCheckValue = False

        self.backgroundImage = PIL.Image.open(r"images/bg.jpeg")
        self.backgroundImage = self.backgroundImage.resize((self.screenWidth, self.screenHeight))
        self.backgroundImage = PIL.ImageTk.PhotoImage(self.backgroundImage)

        self.userImage = PIL.Image.open(r"images/user.png")
        self.userImage = self.userImage.resize((50, 50))
        self.userImage = PIL.ImageTk.PhotoImage(self.userImage)

        self.passwordImage = PIL.Image.open(r"images/password.png")
        self.passwordImage = self.passwordImage.resize((50, 50))
        self.passwordImage = PIL.ImageTk.PhotoImage(self.passwordImage)

        self.questionImage = PIL.Image.open(r"images/question.png")
        self.questionImage = self.questionImage.resize((50, 50))
        self.questionImage = PIL.ImageTk.PhotoImage(self.questionImage)

        self.answerImage = PIL.Image.open(r"images/answer.png")
        self.answerImage = self.answerImage.resize((50, 50))
        self.answerImage = PIL.ImageTk.PhotoImage(self.answerImage)

        self.folderImage = PIL.Image.open(r"images/folder.png")
        self.folderImage = self.folderImage.resize((50, 50))
        self.folderImage = PIL.ImageTk.PhotoImage(self.folderImage)
        
        self.extensionKeyImage = PIL.Image.open(r"images/extension.png")
        self.extensionKeyImage = self.extensionKeyImage.resize((50, 50))
        self.extensionKeyImage = PIL.ImageTk.PhotoImage(self.extensionKeyImage)
        
        self.addExtensionImage = PIL.Image.open(r"images/add.png")
        self.addExtensionImage = self.addExtensionImage.resize((30, 30))
        self.addExtensionImage = PIL.ImageTk.PhotoImage(self.addExtensionImage)

        self.facebookImage = PIL.Image.open(r"images/facebook.png")
        self.facebookImage = self.facebookImage.resize((40, 40))
        self.facebookImage = PIL.ImageTk.PhotoImage(self.facebookImage)

        self.instagramImage = PIL.Image.open(r"images/instagram.png")
        self.instagramImage = self.instagramImage.resize((40, 40))
        self.instagramImage = PIL.ImageTk.PhotoImage(self.instagramImage)

        self.twitterImage = PIL.Image.open(r"images/twitter.webp")
        self.twitterImage = self.twitterImage.resize((40, 40))
        self.twitterImage = PIL.ImageTk.PhotoImage(self.twitterImage)

        self.youtubeImage = PIL.Image.open(r"images/youtube.png")
        self.youtubeImage = self.youtubeImage.resize((40, 40))
        self.youtubeImage = PIL.ImageTk.PhotoImage(self.youtubeImage)

        self.questionsList = ["Forgot Question", "Favourite Food", "Birth Place", "Best Friend", "First Pet Name", "School Name", "Home Town"]

        self.backgroundLabel = Label(self.screen, image=self.backgroundImage)
        self.backgroundLabel.image = self.backgroundImage
        self.backgroundLabel.pack()

        self.setMainFrames()

        messagebox.showinfo("Greetings", "Welcome To Our Services.")
        
        self.screen.mainloop()

    def setMainFrames(self):
        self.setLoginFrame()
        self.setSideFrame()
    
    def setOrganizerFrames(self):
        self.setOrganizerLeftFrame()
        self.setOrganizerRightFrame()
    
    def setAdminPanelFrames(self):
        self.setAdminPanelLeftFrame()
        self.setAdminPanelRightFrame()
    
    def setSideFrame(self):
        self.rightFrame = Frame(self.screen, width=350, height=550, bg="white")
        self.rightFrame.place(x=900, y=170)

        self.accountLabel_1 = Label(self.rightFrame, text="CREATE NEW ACCOUNT", font=("fira code", 14, "bold"), bg="white")
        self.accountLabel_1.place(x=0, y=50, relwidth=1)

        self.loginButton_2 = Button(self.rightFrame, text="Log In", width=18, bd=0, font=("fira code", 16, "bold"), bg="#36802d", command=self.setLoginFrame)
        self.loginButton_2.place(x=50, y=130)

        self.signupButton_1 = Button(self.rightFrame, text="Sign Up", width=18, bd=0, font=("fira code", 16, "bold"), bg="#00FFFF", command=self.setSignupFrame)
        self.signupButton_1.place(x=50, y=220)

        self.forgotButton_1 = Button(self.rightFrame, text="Forgot Password", width=18, bd=0, font=("fira code", 16, "bold"), bg="#FFA500", command=self.setForgotFrame)
        self.forgotButton_1.place(x=50, y=310)

        self.followLabel_1 = Label(self.rightFrame, text="Follow Us On", font=("fira code", 16, "bold"), bg="white", fg="#FF0000")
        self.followLabel_1.place(x=0, y=400, relwidth=1)

        self.facebookButton_1 = Button(self.rightFrame, bd=0, bg="white", image=self.facebookImage, command=self.openFacebook)
        self.facebookButton_1.image = self.facebookImage
        self.facebookButton_1.place(x=50, y=460)

        self.twitterButton_1 = Button(self.rightFrame, bd=0, bg="white", image=self.twitterImage, command=self.openTwitter)
        self.twitterButton_1.image = self.twitterImage
        self.twitterButton_1.place(x=120, y=460)

        self.youtubeButton_1 = Button(self.rightFrame, bd=0, bg="white", image=self.youtubeImage, command=self.openYoutube)
        self.youtubeButton_1.image = self.youtubeImage
        self.youtubeButton_1.place(x=190, y=460)

        self.instagramButton_1 = Button(self.rightFrame, bd=0, bg="white", image=self.instagramImage, command=self.openInstagram)
        self.instagramButton_1.image = self.instagramImage
        self.instagramButton_1.place(x=260, y=460)

        self.loginButton_2.bind("<Enter>", self.onEnter)
        self.loginButton_2.bind("<Leave>", self.onLeave)

        self.signupButton_1.bind("<Enter>", self.onEnter)
        self.signupButton_1.bind("<Leave>", self.onLeave)

        self.forgotButton_1.bind("<Enter>", self.onEnter)
        self.forgotButton_1.bind("<Leave>", self.onLeave)

        self.facebookButton_1.bind("<Enter>", self.onEnter)
        self.facebookButton_1.bind("<Leave>", self.onLeave)

        self.twitterButton_1.bind("<Enter>", self.onEnter)
        self.twitterButton_1.bind("<Leave>", self.onLeave)

        self.youtubeButton_1.bind("<Enter>", self.onEnter)
        self.youtubeButton_1.bind("<Leave>", self.onLeave)

        self.instagramButton_1.bind("<Enter>", self.onEnter)
        self.instagramButton_1.bind("<Leave>", self.onLeave)
    
    def setLoginFrame(self):
        self.leftFrame_1 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.leftFrame_1.place(x=250, y=170)

        self.loginLabel_1 = Label(self.leftFrame_1, text="LOGIN", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.loginLabel_1.place(x=0, y=50, relwidth=1)

        self.usernameLabel_1 = Label(self.leftFrame_1, text="Username", image=self.userImage, compound=LEFT, font=("fira code", 20, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.usernameLabel_1.image = self.userImage
        self.usernameLabel_1.place(x=50, y=150)

        self.passwordLabel_1 = Label(self.leftFrame_1, text="Password", image=self.passwordImage, compound=LEFT, font=("fira code", 20, "bold"), bd=0, bg="#aaaac6", padx=10, pady=10)
        self.passwordLabel_1.image = self.passwordImage
        self.passwordLabel_1.place(x=50, y=220)

        self.usernameEntry_1 = Entry(self.leftFrame_1, textvariable=self.username_1, width=22, font=("fira code", 15, "bold"))
        self.usernameEntry_1.place(x=300, y=160)
        self.usernameEntry_1.focus_set()

        self.passwordEntry_1 = Entry(self.leftFrame_1, textvariable=self.password_1, width=22, font=("fira code", 15, "bold"), show="*")
        self.passwordEntry_1.place(x=300, y=240)

        self.rememberCheck_1 = Checkbutton(self.leftFrame_1, text="Remember me", font=("fira code", 14, "bold"), bg="#aaaac6", pady=10, variable=self.isChecked_1)
        self.rememberCheck_1.place(x=300, y=300)

        self.loginButton_1 = Button(self.leftFrame_1, text="Log In", bd=0, width=23, font=("fira code", 14, "bold"), bg="#36802d", pady=10, command=self.loginUser)
        self.loginButton_1.place(x=300, y=400)

        self.screen.bind("<Return>", self.loginUser)
        self.screen.bind("<Tab>", self.autoFillPassword)

        self.usernameEntry_1.bind("<Enter>", self.onEnter)
        self.usernameEntry_1.bind("<Leave>", self.onLeave)

        self.passwordEntry_1.bind("<Enter>", self.onEnter)
        self.passwordEntry_1.bind("<Leave>", self.onLeave)

        self.rememberCheck_1.bind("<Enter>", self.onEnter)
        self.rememberCheck_1.bind("<Leave>", self.onLeave)

        self.loginButton_1.bind("<Enter>", self.onEnter)
        self.loginButton_1.bind("<Leave>", self.onLeave)

    def setSignupFrame(self):
        self.leftFrame_2 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.leftFrame_2.place(x=250, y=170)

        self.signupLabel_1 = Label(self.leftFrame_2, text="SIGNUP", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.signupLabel_1.place(x=0, y=50, relwidth=1)

        self.usernameLabel_2 = Label(self.leftFrame_2, text="Username", image=self.userImage, compound=LEFT, font=("fira code", 20, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.usernameLabel_2.image = self.userImage
        self.usernameLabel_2.place(x=50, y=150)

        self.passwordLabel_2 = Label(self.leftFrame_2, text="Password", image=self.passwordImage, compound=LEFT, font=("fira code", 20, "bold"), bd=0, bg="#aaaac6", padx=10, pady=10)
        self.passwordLabel_2.image = self.passwordImage
        self.passwordLabel_2.place(x=50, y=220)

        self.usernameEntry_2 = Entry(self.leftFrame_2, textvariable=self.username_2, width=22, font=("fira code", 15, "bold"))
        self.usernameEntry_2.place(x=300, y=160)
        self.usernameEntry_2.focus_set()

        self.passwordEntry_2 = Entry(self.leftFrame_2, textvariable=self.password_2, width=22, font=("fira code", 15, "bold"), show="*")
        self.passwordEntry_2.place(x=300, y=240)

        self.questionsCombobox_1 = ttk.Combobox(self.leftFrame_2, width=16, values=self.questionsList, font=("fira code", 12, "bold"), textvariable=self.selectedQuestion_1)
        self.questionsCombobox_1.place(x=60, y=325)
        self.questionsCombobox_1.current(0)

        self.answerEntry_1 = Entry(self.leftFrame_2, textvariable=self.selectedQuestionAnswer_1, width=22, font=("fira code", 15, "bold"))
        self.answerEntry_1.place(x=300, y=320)

        self.signupButton_2 = Button(self.leftFrame_2, text="Sign Up", bd=0, width=23, font=("fira code", 14, "bold"), bg="#00FFFF", pady=10, command=self.registerUser)
        self.signupButton_2.place(x=300, y=400)
        self.screen.bind("<Return>", self.registerUser)

        self.usernameEntry_2.bind("<Enter>", self.onEnter)
        self.usernameEntry_2.bind("<Leave>", self.onLeave)

        self.passwordEntry_2.bind("<Enter>", self.onEnter)
        self.passwordEntry_2.bind("<Leave>", self.onLeave)

        self.answerEntry_1.bind("<Enter>", self.onEnter)
        self.answerEntry_1.bind("<Leave>", self.onLeave)

        self.signupButton_2.bind("<Enter>", self.onEnter)
        self.signupButton_2.bind("<Leave>", self.onLeave)
    
    def setForgotFrame(self):
        self.leftFrame_3 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.leftFrame_3.place(x=250, y=170)

        self.forgotLabel_1 = Label(self.leftFrame_3, text="FORGOT PASSWORD", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.forgotLabel_1.place(x=0, y=50, relwidth=1)

        self.usernameLabel_3 = Label(self.leftFrame_3, text="Username", image=self.userImage, compound=LEFT, font=("fira code", 20, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.usernameLabel_3.image = self.userImage
        self.usernameLabel_3.place(x=50, y=150)

        self.forgotQuestionLabel = Label(self.leftFrame_3, text="Question", image=self.questionImage, compound=LEFT, font=("fira code", 20, "bold"), bd=0, bg="#aaaac6", padx=10, pady=10)
        self.forgotQuestionLabel.image = self.questionImage
        self.forgotQuestionLabel.place(x=50, y=220)

        self.forgotAnswerLabel = Label(self.leftFrame_3, text="Answer", image=self.answerImage, compound=LEFT, font=("fira code", 20, "bold"), bd=0, bg="#aaaac6", padx=10, pady=10)
        self.forgotAnswerLabel.image = self.answerImage
        self.forgotAnswerLabel.place(x=50, y=300)

        self.usernameEntry_3 = Entry(self.leftFrame_3, textvariable=self.username_3, width=22, font=("fira code", 15, "bold"))
        self.usernameEntry_3.place(x=300, y=160)
        self.usernameEntry_3.focus_set()

        self.answerEntry_2 = Entry(self.leftFrame_3, textvariable=self.selectedQuestionAnswer_2, width=22, font=("fira code", 15, "bold"))
        self.answerEntry_2.place(x=300, y=320)

        self.questionsCombobox_2 = ttk.Combobox(self.leftFrame_3, width=24, values=self.questionsList, font=("fira code", 12, "bold"), textvariable=self.selectedQuestion_2)
        self.questionsCombobox_2.place(x=300, y=240)
        self.questionsCombobox_2.current(0)

        self.forgotPasswordButton_2 = Button(self.leftFrame_3, text="Submit", bd=0, width=22, font=("fira code", 15, "bold"), bg="#FFA500", pady=10, command=self.getPassword)
        self.forgotPasswordButton_2.place(x=300, y=410)

        self.screen.bind("<Return>", self.getPassword)

        self.usernameEntry_3.bind("<Enter>", self.onEnter)
        self.usernameEntry_3.bind("<Leave>", self.onLeave)

        self.answerEntry_2.bind("<Enter>", self.onEnter)
        self.answerEntry_2.bind("<Leave>", self.onLeave)

        self.forgotPasswordButton_2.bind("<Enter>", self.onEnter)
        self.forgotPasswordButton_2.bind("<Leave>", self.onLeave)

    def setOrganizerRightFrame(self):
        self.rightFrame_2 = Frame(self.screen, width=350, height=550, bg="white")
        self.rightFrame_2.place(x=900, y=170)

        self.OrganizeLabel_2 = Label(self.rightFrame_2, text="ORGANIZE YOUR FILES", font=("fira code", 14, "bold"), bg="white")
        self.OrganizeLabel_2.place(x=0, y=50, relwidth=1)

        self.organizeButton_2 = Button(self.rightFrame_2, text="Organize Files", width=18, bd=0, font=("fira code", 16, "bold"), bg="#36802d", command=self.setOrganizerLeftFrame)
        self.organizeButton_2.place(x=50, y=130)

        self.historyButton_1 = Button(self.rightFrame_2, text="History", width=18, bd=0, font=("fira code", 16, "bold"), bg="#00FFFF", command=self.setHistoryFrame)
        self.historyButton_1.place(x=50, y=220)

        self.homeButton_1 = Button(self.rightFrame_2, text="Home", width=18, bd=0, font=("fira code", 16, "bold"), bg="#FFA500", command=self.logoutUser)
        self.homeButton_1.place(x=50, y=310)

        self.followLabel_2 = Label(self.rightFrame_2, text="Follow Us On", font=("fira code", 16, "bold"), bg="white", fg="#FF0000")
        self.followLabel_2.place(x=0, y=400, relwidth=1)

        self.facebookButton_2 = Button(self.rightFrame_2, bd=0, bg="white", image=self.facebookImage, command=self.openFacebook)
        self.facebookButton_2.image = self.facebookImage
        self.facebookButton_2.place(x=50, y=460)

        self.twitterButton_2 = Button(self.rightFrame_2, bd=0, bg="white", image=self.twitterImage, command=self.openTwitter)
        self.twitterButton_2.image = self.twitterImage
        self.twitterButton_2.place(x=120, y=460)

        self.youtubeButton_2 = Button(self.rightFrame_2, bd=0, bg="white", image=self.youtubeImage, command=self.openYoutube)
        self.youtubeButton_2.image = self.youtubeImage
        self.youtubeButton_2.place(x=190, y=460)

        self.instagramButton_2 = Button(self.rightFrame_2, bd=0, bg="white", image=self.instagramImage, command=self.openInstagram)
        self.instagramButton_2.image = self.instagramImage
        self.instagramButton_2.place(x=260, y=460)

        self.organizeButton_2.bind("<Enter>", self.onEnter)
        self.organizeButton_2.bind("<Leave>", self.onLeave)

        self.historyButton_1.bind("<Enter>", self.onEnter)
        self.historyButton_1.bind("<Leave>", self.onLeave)

        self.homeButton_1.bind("<Enter>", self.onEnter)
        self.homeButton_1.bind("<Leave>", self.onLeave)

        self.facebookButton_2.bind("<Enter>", self.onEnter)
        self.facebookButton_2.bind("<Leave>", self.onLeave)

        self.twitterButton_2.bind("<Enter>", self.onEnter)
        self.twitterButton_2.bind("<Leave>", self.onLeave)

        self.youtubeButton_2.bind("<Enter>", self.onEnter)
        self.youtubeButton_2.bind("<Leave>", self.onLeave)

        self.instagramButton_2.bind("<Enter>", self.onEnter)
        self.instagramButton_2.bind("<Leave>", self.onLeave)
    
    def setOrganizerLeftFrame(self):
        self.leftFrame_4 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.leftFrame_4.place(x=250, y=170)

        self.organizeLabel_1 = Label(self.leftFrame_4, text="ORGANIZE FILES", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.organizeLabel_1.place(x=0, y=50, relwidth=1)

        self.folderPathLabel_1 = Label(self.leftFrame_4, text="Folder Path", image=self.folderImage, compound=LEFT, font=("fira code", 16, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.folderPathLabel_1.image = self.folderImage
        self.folderPathLabel_1.place(x=50, y=150)

        self.folderPathEntry_1 = Entry(self.leftFrame_4, textvariable=self.folderPath_1, width=22, font=("fira code", 15, "bold"))
        self.folderPathEntry_1.place(x=300, y=160)
        self.folderPathEntry_1.focus_set()

        self.organizeButton_1 = Button(self.leftFrame_4, text="Organize", bd=0, width=22, font=("fira code", 15, "bold"), bg="#36802d", pady=10, command=self.validateFolderPath)
        self.organizeButton_1.place(x=300, y=260)

        self.changePasswordButton_1 = Button(self.leftFrame_4, text="Change Password?", font=("fira code", 12, "bold"), fg="blue", bg="#aaaac6", bd=0, command=self.setChangePasswordFrame)
        self.changePasswordButton_1.place(x=300, y=210)

        self.screen.bind("<Return>", self.validateFolderPath)

        self.folderPathEntry_1.bind("<Enter>", self.onEnter)
        self.folderPathEntry_1.bind("<Leave>", self.onLeave)

        self.organizeButton_1.bind("<Enter>", self.onEnter)
        self.organizeButton_1.bind("<Leave>", self.onLeave)

        self.changePasswordButton_1.bind("<Enter>", self.onEnter)
        self.changePasswordButton_1.bind("<Leave>", self.onLeave)
    
    def setChangePasswordFrame(self):
        self.changePasswordFrame_1 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.changePasswordFrame_1.place(x=250, y=170)

        self.changePasswordLabel_1 = Label(self.changePasswordFrame_1, text="CHANGE PASSWORD", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.changePasswordLabel_1.place(x=0, y=50, relwidth=1)

        self.oldPasswordLabel_1 = Label(self.changePasswordFrame_1, text="Old Password", image=self.passwordImage, compound=LEFT, font=("fira code", 16, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.oldPasswordLabel_1.image = self.passwordImage
        self.oldPasswordLabel_1.place(x=40, y=150)

        self.newPasswordLabel_1 = Label(self.changePasswordFrame_1, text="New Password", image=self.passwordImage, compound=LEFT, font=("fira code", 16, "bold"), bd=0, bg="#aaaac6", padx=10, pady=10)
        self.newPasswordLabel_1.image = self.passwordImage
        self.newPasswordLabel_1.place(x=40, y=210)

        self.confirmPasswordLabel_1 = Label(self.changePasswordFrame_1, text="Confirm Password", image=self.passwordImage, compound=LEFT, font=("fira code", 16, "bold"), bd=0, bg="#aaaac6", padx=10, pady=10)
        self.confirmPasswordLabel_1.image = self.passwordImage
        self.confirmPasswordLabel_1.place(x=40, y=280)

        self.oldPasswordEntry_1 = Entry(self.changePasswordFrame_1, textvariable=self.oldPassword_1, width=20, font=("fira code", 14, "bold"), show="*")
        self.oldPasswordEntry_1.place(x=350, y=160)
        self.oldPasswordEntry_1.focus_set()

        self.newPasswordEntry_1 = Entry(self.changePasswordFrame_1, textvariable=self.newPassword_1, width=20, font=("fira code", 14, "bold"), show="*")
        self.newPasswordEntry_1.place(x=350, y=230)

        self.confirmPasswordEntry_1 = Entry(self.changePasswordFrame_1, textvariable=self.confirmPassword_1, width=20, font=("fira code", 14, "bold"), show="*")
        self.confirmPasswordEntry_1.place(x=350, y=300)

        self.changePasswordButton_1 = Button(self.changePasswordFrame_1, text="Change Password", bd=0, width=20, font=("fira code", 14, "bold"), bg="#FFA500", pady=10, command=self.changePassword)
        self.changePasswordButton_1.place(x=350, y=390)

        self.screen.bind("<Return>", self.changePassword)

        self.oldPasswordEntry_1.bind("<Enter>", self.onEnter)
        self.oldPasswordEntry_1.bind("<Leave>", self.onLeave)

        self.newPasswordEntry_1.bind("<Enter>", self.onEnter)
        self.newPasswordEntry_1.bind("<Leave>", self.onLeave)

        self.confirmPasswordEntry_1.bind("<Enter>", self.onEnter)
        self.confirmPasswordEntry_1.bind("<Leave>", self.onLeave)

        self.changePasswordButton_1.bind("<Enter>", self.onEnter)
        self.changePasswordButton_1.bind("<Leave>", self.onLeave)

    def setChooseFilesFrame(self):
        self.folderPathEntry_1.delete(0, END)

        self.leftFrame_6 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.leftFrame_6.place(x=250, y=170)

        self.chooseLabel_1 = Label(self.leftFrame_6, text="CHOOSE FILES", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.chooseLabel_1.place(x=0, y=50, relwidth=1)

        self.chooseFilesFrame_1 = Frame(self.leftFrame_6, bg="#aaaac6")
        self.chooseFilesFrame_1.place(x=0, y=150)

        self.chooseFilesListbox_1 = Listbox(self.chooseFilesFrame_1, width=57, height=10, bg="#aaaac6", font=("fira code", 12, "bold"))
        self.chooseFilesListbox_1.pack(side=LEFT, fill=Y)

        self.chooseFilesScroll_1 = Scrollbar(self.chooseFilesFrame_1, orient=VERTICAL, command=self.chooseFilesListbox_1.yview)
        self.chooseFilesScroll_1.pack(side=RIGHT, fill=Y)
        self.chooseFilesListbox_1.config(yscrollcommand=self.chooseFilesScroll_1.set)

        self.selectAllButton_1 = Button(self.leftFrame_6, text="Select All", bg="#00FFFF", font=("fira code", 14, "bold"), command=self.selectAll)
        self.selectAllButton_1.place(x=50, y=460)

        self.varList = [f"self.checkFileType{i}" for i in range(len(self.extensions_dictionary))]

        self.x, self.y = 50, 0
        self.varCount = 0

        for self.fileType in self.extensions_dictionary:
            self.varList[self.varCount] = BooleanVar()
            self.text = self.fileType.split("_")[0].title()

            Checkbutton(self.chooseFilesListbox_1, bg="#aaaac6", pady=10, variable=self.varList[self.varCount]).place(x=0, y=self.y)
            Label(self.chooseFilesListbox_1, text=self.text, bg="#aaaac6", font=("fira code", 14, "bold")).place(x=self.x, y=self.y)

            self.varCount += 1
            self.y += 50

        self.organizeButton_3 = Button(self.leftFrame_6, text="Organize", bd=0, width=22, font=("fira code", 15, "bold"), bg="#36802d", pady=10, command=self.organizeFiles)
        self.organizeButton_3.place(x=310, y=450)

        self.screen.bind("<Return>", self.organizeFiles)

        self.selectAllButton_1.bind("<Enter>", self.onEnter)
        self.selectAllButton_1.bind("<Leave>", self.onLeave)

        self.organizeButton_3.bind("<Enter>", self.onEnter)
        self.organizeButton_3.bind("<Leave>", self.onLeave)

    def setHistoryFrame(self):
        self.leftFrame_5 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.leftFrame_5.place(x=250, y=170)

        self.historyLabel_1 = Label(self.leftFrame_5, text="History", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.historyLabel_1.place(x=0, y=50, relwidth=1)

        self.historyCanvasFrame_1 = Frame(self.leftFrame_5, bg="#aaaac6")
        self.historyCanvasFrame_1.place(x=0, y=150)

        self.historyScroll_1 = Scrollbar(self.historyCanvasFrame_1)
        self.historyScroll_1.pack(side=RIGHT, fill=Y)

        # self.historyScroll_2 = Scrollbar(self.historyCanvasFrame_1, orient=HORIZONTAL)
        # self.historyScroll_2.pack(side=BOTTOM, fill=X)

        # self.historyListbox_1 = Text(self.historyCanvasFrame_1, height=10, width=57, bg="#aaaac6", fg="green", font=("fira code", 12, "bold"), bd=0, yscrollcommand=self.historyScroll_1.set, xscrollcommand=self.historyScroll_2.set, wrap=WORD)
        # self.historyListbox_1.pack(expand=0, side=LEFT, fill=BOTH)
        # self.historyScroll_2.config(command=self.historyListbox_1.xview)

        self.historyListbox_1 = Text(self.historyCanvasFrame_1, height=10, width=57, bg="#aaaac6", fg="green", font=("fira code", 12, "bold"), bd=0, yscrollcommand=self.historyScroll_1.set, wrap=WORD)
        self.historyListbox_1.pack(expand=0, side=LEFT, fill=BOTH)
        self.historyScroll_1.config(command=self.historyListbox_1.yview)

        self.deleteHistoryButton_1 = Button(self.leftFrame_5, text="Delete History", width=18, bd=0, font=("fira code", 14, "bold"), bg="#FFA500", pady=10, command=self.deleteHistory)
        self.deleteHistoryButton_1.place(x=50, y=450)

        self.deleteAccountButton_1 = Button(self.leftFrame_5, text="Delete Account", width=18, bd=0, font=("fira code", 14, "bold"), bg="#FFA500", pady=10, command=self.deleteAccount)
        self.deleteAccountButton_1.place(x=380, y=450)

        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)
        self.userDataKey = list(self.gotUserData.keys())[2]

        self.gotUserHistoryData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", None)

        self.filePathsList = []

        for self.historyKey, self.historyValue in self.gotUserHistoryData.items():
            if self.historyKey != "Status":
                self.filePathsList.append(f"{self.historyKey} {self.historyValue}")

        for self.filePathIndex in range(len(self.filePathsList)):
            self.historyListbox_1.insert(END, self.filePathsList[self.filePathIndex] + "\n")

        self.historyListbox_1.configure(state=DISABLED)

        self.deleteHistoryButton_1.bind("<Enter>", self.onEnter)
        self.deleteHistoryButton_1.bind("<Leave>", self.onLeave)

        self.deleteAccountButton_1.bind("<Enter>", self.onEnter)
        self.deleteAccountButton_1.bind("<Leave>", self.onLeave)
    
    def setAdminPanelRightFrame(self):
        self.adminPanelRightFrame_1 = Frame(self.screen, width=350, height=550, bg="white")
        self.adminPanelRightFrame_1.place(x=900, y=170)

        self.controlPanelLabel_1 = Label(self.adminPanelRightFrame_1, text="Admin Controls", font=("fira code", 14, "bold"), bg="white")
        self.controlPanelLabel_1.place(x=0, y=50, relwidth=1)

        self.editUserButton_1 = Button(self.adminPanelRightFrame_1, text="Edit User", width=18, bd=0, font=("fira code", 16, "bold"), bg="#36802d", command=self.setAdminPanelLeftFrame)
        self.editUserButton_1.place(x=50, y=130)

        self.deleteUserButton_1 = Button(self.adminPanelRightFrame_1, text="Delete User", width=18, bd=0, font=("fira code", 16, "bold"), bg="#00FFFF", command=self.setDeleteUserByAdminFrame)
        self.deleteUserButton_1.place(x=50, y=230)

        self.updateExtensionsButton_1 = Button(self.adminPanelRightFrame_1, text="Update Extensions", width=18, bd=0, font=("fira code", 16, "bold"), bg="#FFA500", command=self.setUpdateExtensionsFrame)
        self.updateExtensionsButton_1.place(x=50, y=330)

        self.homeButton_2 = Button(self.adminPanelRightFrame_1, text="Home", width=18, bd=0, font=("fira code", 16, "bold"), bg="red", command=self.logoutUser)
        self.homeButton_2.place(x=50, y=430)
        
        self.editUserButton_1.bind("<Enter>", self.onEnter)
        self.editUserButton_1.bind("<Leave>", self.onLeave)
        
        self.deleteUserButton_1.bind("<Enter>", self.onEnter)
        self.deleteUserButton_1.bind("<Leave>", self.onLeave)
        
        self.updateExtensionsButton_1.bind("<Enter>", self.onEnter)
        self.updateExtensionsButton_1.bind("<Leave>", self.onLeave)
        
        self.homeButton_2.bind("<Enter>", self.onEnter)
        self.homeButton_2.bind("<Leave>", self.onLeave)

    def setAdminPanelLeftFrame(self):
        self.adminPanelFrame_1 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.adminPanelFrame_1.place(x=250, y=170)

        self.adminPanelLabel_1 = Label(self.adminPanelFrame_1, text="Admin Panel", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.adminPanelLabel_1.place(x=0, y=50, relwidth=1)

        self.adminEditUserFrame_1 = Frame(self.adminPanelFrame_1, bg="#aaaac6")
        self.adminEditUserFrame_1.place(x=0, y=150)

        self.adminEditUserScroll_1 = Scrollbar(self.adminEditUserFrame_1)
        self.adminEditUserScroll_1.pack(side=RIGHT, fill=Y)

        self.adminListBox_1 = Listbox(self.adminEditUserFrame_1, width=48, height=8, fg="red", bg="#aaaac6", selectbackground="green", font=("fira code", 15, "bold"))
        self.adminListBox_1.pack(padx=0, pady=0, expand=YES, fill=BOTH)

        self.adminEditUserScroll_1.config(command=self.adminListBox_1.yview)

        self.getUsers = self.userDatabase.get("/filemanager-2febc-default-rtdb:/", None)
        self.getUsersList = list(self.getUsers.keys())[1:]

        self.x, self.y = 0, 0

        for self.getUserIndex in range(len(self.getUsersList)):
            Radiobutton(self.adminListBox_1, text=f"{self.getUsersList[self.getUserIndex]}", font=("fira code", 16, "bold"), bg="#aaaac6", variable=self.selectUser, value=self.getUserIndex).place(x=self.x, y=self.y)
            self.y += 50

        self.editUserButton_2 = Button(self.adminPanelFrame_1, text="Edit User", width=18, bd=0, font=("fira code", 14, "bold"), bg="#36802d", pady=10, command=self.setEditUserByAdminFrame)
        self.editUserButton_2.place(x=220, y=450)
        
        self.editUserButton_2.bind("<Enter>", self.onEnter)
        self.editUserButton_2.bind("<Leave>", self.onLeave)

    def setEditUserByAdminFrame(self):
        self.selectedUserId = self.selectUser.get()

        self.selectedUserByAdmin = self.getUsersList[self.selectedUserId]
        self.getUserFullInfo = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.selectedUserByAdmin}", None)
        self.getUserDataKey = list(self.getUserFullInfo.keys())[0]
        self.getUserDataDictionary = self.getUserFullInfo[self.getUserDataKey]

        self.adminPanelEditUserFrame_1 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.adminPanelEditUserFrame_1.place(x=250, y=170)

        self.adminPanelLabel_1 = Label(self.adminPanelEditUserFrame_1, text="Edit User", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.adminPanelLabel_1.place(x=0, y=50, relwidth=1)

        self.adminEditUserFrame_2 = Frame(self.adminPanelEditUserFrame_1, bg="#aaaac6")
        self.adminEditUserFrame_2.place(x=0, y=150)

        self.adminEditUserScroll_2 = Scrollbar(self.adminEditUserFrame_2)
        self.adminEditUserScroll_2.pack(side=RIGHT, fill=Y)

        self.adminListBox_2 = Listbox(self.adminEditUserFrame_2, width=48, height=6, fg="red", bg="#aaaac6", selectbackground="green", font=("fira code", 15, "bold"))
        self.adminListBox_2.pack(padx=0, pady=0, expand=YES, fill=BOTH)
        self.adminEditUserScroll_2.config(command=self.adminListBox_2.yview)

        self.adminCheckButton_1 = Checkbutton(self.adminPanelEditUserFrame_1, text="Admin", font=("fira code", 16, "bold"), bg="#aaaac6", pady=10, variable=self.adminCheckVar_1)
        self.adminCheckButton_1.place(x=50, y=390)

        self.statusCheckButton_1 = Checkbutton(self.adminPanelEditUserFrame_1, text="Status", font=("fira code", 16, "bold"), bg="#aaaac6", pady=10, variable=self.statusCheckVar_1)
        self.statusCheckButton_1.place(x=50, y=440)

        for self.getUserDataKey, self.getUserDataValue in self.getUserDataDictionary.items():
            if self.getUserDataKey != "Admin" and self.getUserDataKey != "Status":
                self.adminListBox_2.insert(END, f"{self.getUserDataKey} : {self.getUserDataValue}")

        self.adminCheckVar_1.set(self.getUserDataDictionary["Admin"])
        self.statusCheckVar_1.set(self.getUserDataDictionary["Status"])

        self.saveUserButton_1 = Button(self.adminPanelEditUserFrame_1, text="Save User", width=18, bd=0, font=("fira code", 14, "bold"), bg="#36802d", pady=10, command=self.saveUserDataValues)
        self.saveUserButton_1.place(x=370, y=410)
        
        self.adminCheckButton_1.bind("<Enter>", self.onEnter)
        self.adminCheckButton_1.bind("<Leave>", self.onLeave)
        
        self.statusCheckButton_1.bind("<Enter>", self.onEnter)
        self.statusCheckButton_1.bind("<Leave>", self.onLeave)
        
        self.saveUserButton_1.bind("<Enter>", self.onEnter)
        self.saveUserButton_1.bind("<Leave>", self.onLeave)

    def setDeleteUserByAdminFrame(self):
        self.adminPanelDeleteUserFrame_1 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.adminPanelDeleteUserFrame_1.place(x=250, y=170)

        self.adminPanelLabel_2 = Label(self.adminPanelDeleteUserFrame_1, text="Delete User", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.adminPanelLabel_2.place(x=0, y=50, relwidth=1)

        self.adminDeleteUserFrame_2 = Frame(self.adminPanelDeleteUserFrame_1, bg="#aaaac6")
        self.adminDeleteUserFrame_2.place(x=0, y=150)

        self.adminDeleteUserScroll_2 = Scrollbar(self.adminDeleteUserFrame_2)
        self.adminDeleteUserScroll_2.pack(side=RIGHT, fill=Y)

        self.adminListBox_3 = Listbox(self.adminDeleteUserFrame_2, width=48, height=6, fg="red", bg="#aaaac6", selectbackground="green", font=("fira code", 15, "bold"))
        self.adminListBox_3.pack(padx=0, pady=0, expand=YES, fill=BOTH)
        self.adminDeleteUserScroll_2.config(command=self.adminListBox_3.yview)

        self.getUsers = self.userDatabase.get("/filemanager-2febc-default-rtdb:/", None)
        self.getUsersList = list(self.getUsers.keys())[1:]

        self.nonAdminUsers = []

        for self.checkAdminValue in self.getUsersList:
            self.getUserInfoByAdmin = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.checkAdminValue}", None)

            self.getUserInfoByAdminKey = list(self.getUserInfoByAdmin.keys())[0]

            if not self.getUserInfoByAdmin[self.getUserInfoByAdminKey]["Admin"]:
                self.nonAdminUsers.append(self.checkAdminValue)

        self.checkUsersList = [f"self.checkUserByAdmin{i}" for i in range(len(self.nonAdminUsers))]

        self.x, self.y = 50, 0
        self.userCount = 0

        for self.user in self.nonAdminUsers:
            self.checkUsersList[self.userCount] = BooleanVar()

            Checkbutton(self.adminListBox_3, bg="#aaaac6", pady=10, variable=self.checkUsersList[self.userCount]).place(x=0, y=self.y)
            Label(self.adminListBox_3, text=self.user, bg="#aaaac6", font=("fira code", 14, "bold")).place(x=self.x, y=self.y)

            self.userCount += 1
            self.y += 50

        self.selectAllButton_2 = Button(self.adminPanelDeleteUserFrame_1, text="Select All", bg="#00FFFF", font=("fira code", 14, "bold"), command=self.selectAllUsersByAdmin)
        self.selectAllButton_2.place(x=50, y=420)

        self.deleteUserButton_1 = Button(self.adminPanelDeleteUserFrame_1, text="Delete User", width=18, bd=0, font=("fira code", 14, "bold"), bg="#36802d", pady=10, command=self.deleteUserByAdmin)
        self.deleteUserButton_1.place(x=380, y=410)
        
        self.selectAllButton_2.bind("<Enter>", self.onEnter)
        self.selectAllButton_2.bind("<Leave>", self.onLeave)
        
        self.deleteUserButton_1.bind("<Enter>", self.onEnter)
        self.deleteUserButton_1.bind("<Leave>", self.onLeave)

    def setUpdateExtensionsFrame(self):
        self.adminPanelUpdateExtensionsFrame_1 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.adminPanelUpdateExtensionsFrame_1.place(x=250, y=170)

        self.adminPanelLabel_3 = Label(self.adminPanelUpdateExtensionsFrame_1, text="Update Extensions", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.adminPanelLabel_3.place(x=0, y=50, relwidth=1)

        self.adminUpdateExtensionsFrame_1 = Frame(self.adminPanelUpdateExtensionsFrame_1, bg="#aaaac6")
        self.adminUpdateExtensionsFrame_1.place(x=0, y=150)

        self.adminUpdateExtensionsScroll_1 = Scrollbar(self.adminUpdateExtensionsFrame_1)
        self.adminUpdateExtensionsScroll_1.pack(side=RIGHT, fill=Y)

        self.adminListBox_4 = Text(self.adminUpdateExtensionsFrame_1, height=8, width=52, bg="#aaaac6", fg="red", font=("fira code", 14, "bold"), bd=0, yscrollcommand=self.adminUpdateExtensionsScroll_1.set, wrap=WORD)
        self.adminListBox_4.pack(expand=0, side=LEFT, fill=BOTH)

        self.adminUpdateExtensionsScroll_1.config(command=self.adminListBox_4.yview)

        for self.extensionKey, self.extensionValue in self.extensions_dictionary.items():
            self.adminListBox_4.insert(END, f"{self.extensionKey} : {self.extensionValue}\n\n")

        self.addKeyButton_1 = Button(self.adminPanelUpdateExtensionsFrame_1, text="Add Key", width=18, bg="#00FFFF", font=("fira code", 14, "bold"), command=self.setAddKeyToExtensionsFrame)
        self.addKeyButton_1.place(x=50, y=460)

        self.addValueButton_1 = Button(self.adminPanelUpdateExtensionsFrame_1, text="Add Value", width=18, bd=0, font=("fira code", 14, "bold"), bg="#FFA500", command=self.setAddValueToExtensionsFrame)
        self.addValueButton_1.place(x=380, y=460)
        
        self.addKeyButton_1.bind("<Enter>", self.onEnter)
        self.addKeyButton_1.bind("<Leave>", self.onLeave)
        
        self.addValueButton_1.bind("<Enter>", self.onEnter)
        self.addValueButton_1.bind("<Leave>", self.onLeave)

    def setAddKeyToExtensionsFrame(self):
        self.adminPanelAddKeyFrame_1 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.adminPanelAddKeyFrame_1.place(x=250, y=170)

        self.adminPanelLabel_4 = Label(self.adminPanelAddKeyFrame_1, text="Add Key", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.adminPanelLabel_4.place(x=0, y=50, relwidth=1)
        
        self.extensionKeyLabel_1 = Label(self.adminPanelAddKeyFrame_1, text="Extension Key", image=self.extensionKeyImage, compound=LEFT, font=("fira code", 14, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.extensionKeyLabel_1.image = self.extensionKeyImage
        self.extensionKeyLabel_1.place(x=30, y=150)
        
        self.extensionValueLabel_1 = Label(self.adminPanelAddKeyFrame_1, text="Extension Value", image=self.extensionKeyImage, compound=LEFT, font=("fira code", 14, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.extensionValueLabel_1.image = self.extensionKeyImage
        self.extensionValueLabel_1.place(x=30, y=250)
        
        self.extensionKeyEntry_1 = Entry(self.adminPanelAddKeyFrame_1, textvariable=self.extensionKey_1, width=16, font=("fira code", 14, "bold"))
        self.extensionKeyEntry_1.place(x=330, y=160)
        self.extensionKeyEntry_1.focus_set()
        
        self.extensionValueEntry_1 = Entry(self.adminPanelAddKeyFrame_1, textvariable=self.extensionValue_1, width=16, font=("fira code", 14, "bold"))
        self.extensionValueEntry_1.place(x=330, y=260)
        
        self.extensionValueButton_1 = Button(self.adminPanelAddKeyFrame_1, bd=0, bg="#aaaac6", image=self.addExtensionImage, command=self.addExtensionByAdmin)
        self.extensionValueButton_1.image = self.addExtensionImage
        self.extensionValueButton_1.place(x=550, y=260)
        
        self.addExtensionButton_1 = Button(self.adminPanelAddKeyFrame_1, text="Add", width=16, bd=0, font=("fira code", 14, "bold"), bg="#FFA500", command=self.saveExtensionByAdmin)
        self.addExtensionButton_1.place(x=330, y=360)
        
        self.extensionKeyEntry_1.bind("<Enter>", self.onEnter)
        self.extensionKeyEntry_1.bind("<Leave>", self.onLeave)
        
        self.extensionValueEntry_1.bind("<Enter>", self.onEnter)
        self.extensionValueEntry_1.bind("<Leave>", self.onLeave)
        
        self.extensionValueButton_1.bind("<Enter>", self.onEnter)
        self.extensionValueButton_1.bind("<Leave>", self.onLeave)
        
        self.addExtensionButton_1.bind("<Enter>", self.onEnter)
        self.addExtensionButton_1.bind("<Leave>", self.onLeave)

    def setAddValueToExtensionsFrame(self):
        self.adminPanelAddValueFrame_1 = Frame(self.screen, width=650, height=550, bg="#aaaac6")
        self.adminPanelAddValueFrame_1.place(x=250, y=170)

        self.adminPanelLabel_5 = Label(self.adminPanelAddValueFrame_1, text="Add Value", font=("fira code", 30, "bold"), bg="#aaaac6")
        self.adminPanelLabel_5.place(x=0, y=50, relwidth=1)
        
        self.extensionKeyLabel_2 = Label(self.adminPanelAddValueFrame_1, text="Extension Key", image=self.extensionKeyImage, compound=LEFT, font=("fira code", 14, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.extensionKeyLabel_2.image = self.extensionKeyImage
        self.extensionKeyLabel_2.place(x=30, y=150)
        
        self.extensionValueLabel_2 = Label(self.adminPanelAddValueFrame_1, text="Extension Value", image=self.extensionKeyImage, compound=LEFT, font=("fira code", 14, "bold"), bd=0, bg="#aaaac6", padx=10)
        self.extensionValueLabel_2.image = self.extensionKeyImage
        self.extensionValueLabel_2.place(x=30, y=250)
        
        self.extensionKeyEntry_2 = Entry(self.adminPanelAddValueFrame_1, textvariable=self.extensionKey_2, width=16, font=("fira code", 14, "bold"))
        self.extensionKeyEntry_2.place(x=330, y=160)
        self.extensionKeyEntry_2.focus_set()
        
        self.extensionValueEntry_2 = Entry(self.adminPanelAddValueFrame_1, textvariable=self.extensionValue_2, width=16, font=("fira code", 14, "bold"))
        self.extensionValueEntry_2.place(x=330, y=260)
        
        self.extensionValueButton_2 = Button(self.adminPanelAddValueFrame_1, bd=0, bg="#aaaac6", image=self.addExtensionImage, command=self.updateExtensionsByAdmin)
        self.extensionValueButton_2.image = self.addExtensionImage
        self.extensionValueButton_2.place(x=550, y=260)
        
        self.addExtensionButton_2 = Button(self.adminPanelAddValueFrame_1, text="Add", width=16, bd=0, font=("fira code", 14, "bold"), bg="#FFA500", command=self.modifyExtensionsByAdmin)
        self.addExtensionButton_2.place(x=330, y=360)
        
        self.extensionKeyEntry_2.bind("<Enter>", self.onEnter)
        self.extensionKeyEntry_2.bind("<Leave>", self.onLeave)
        
        self.extensionValueEntry_2.bind("<Enter>", self.onEnter)
        self.extensionValueEntry_2.bind("<Leave>", self.onLeave)
        
        self.extensionValueButton_2.bind("<Enter>", self.onEnter)
        self.extensionValueButton_2.bind("<Leave>", self.onLeave)
        
        self.addExtensionButton_2.bind("<Enter>", self.onEnter)
        self.addExtensionButton_2.bind("<Leave>", self.onLeave)

    def addExtensionByAdmin(self):
        self.extensionValue_4 = self.extensionValue_1.get()
        
        if self.extensionValue_4:
            if self.extensionValue_4 not in self.addedExtensions:
                self.addedExtensions.append(self.extensionValue_4)
                self.extensionValueEntry_1.delete(0, END)
                self.extensionValueEntry_1.focus_set()
        
        else:
            if messagebox.showwarning("Warning", "All fields are required."):
                self.extensionValueEntry_1.focus_set()
    
    def saveExtensionByAdmin(self):
        self.extensionKey_4 = self.extensionKey_1.get()
        self.extensionValue_4 = self.extensionValue_1.get()
        
        if self.extensionValue_4:
            if self.extensionValue_4 not in self.addedExtensions:
                self.addedExtensions.append(self.extensionValue_4)
                self.extensionValueEntry_1.delete(0, END)
                self.extensionValueEntry_1.focus_set()
        
        else:
            messagebox.showwarning("Warning", "Please add atleast one extension.")
            self.extensionValueEntry_1.focus_set()
        
        if self.extensionKey_4:
            if self.addedExtensions:
                if self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.getDatabaseKey_0}", self.extensionKey_4, self.addedExtensions):
                    messagebox.showinfo("Success", "Extensions are successfully updated.")
                    self.extensionKeyEntry_1.delete(0, END)
                    self.extensionKeyEntry_1.focus_set()
        
        else:
            if messagebox.showwarning("Warning", "All fields are required."):
                self.extensionKeyEntry_1.focus_set()
    
    def updateExtensionsByAdmin(self):
        self.extensionValue_3 = self.extensionValue_2.get()
        
        if self.extensionValue_3:
            if self.extensionValue_3 not in self.updatedExtensions:
                self.updatedExtensions.append(self.extensionValue_3)
                self.extensionValueEntry_2.delete(0, END)
                self.extensionValueEntry_2.focus_set()
        
        else:
            if messagebox.showwarning("Warning", "Please add atleast one extension."):
                self.extensionValueEntry_2.focus_set()
    
    def modifyExtensionsByAdmin(self):
        self.extensionKey_3 = self.extensionKey_2.get()
        self.extensionValue_3 = self.extensionValue_2.get()
        
        if self.extensionValue_3:
            if self.extensionValue_3 not in self.updatedExtensions:
                self.updatedExtensions.append(self.extensionValue_3)
                self.extensionValueEntry_2.delete(0, END)
                self.extensionValueEntry_2.focus_set()
        
        else:
            if messagebox.showwarning("Warning", "All fields are required."):
                self.extensionValueEntry_2.focus_set()
        
        if self.extensionKey_3:
            if self.updatedExtensions:
                self.updatedExtensionsList = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.getDatabaseKey_0}/{self.extensionKey_3}", None)
                self.updatedExtensionsList.extend(self.updatedExtensions)
                
                self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.getDatabaseKey_0}/", self.extensionKey_3, self.updatedExtensionsList)
                
                messagebox.showinfo("Success", "Extensions are successfully updated.")
                
                self.extensionKeyEntry_2.delete(0, END)
                self.extensionKeyEntry_2.focus_set()
        
        else:
            if messagebox.showwarning("Warning", "All fields are required."):
                self.extensionKeyEntry_2.focus_set()

    def registerUser(self, event=None):
        self.usernameRegister = self.username_2.get()
        self.passwordRegister = self.password_2.get()
        self.selectedQuestionRegister = self.selectedQuestion_1.get()
        self.selectedQuestionAnswerRegister = self.selectedQuestionAnswer_1.get()

        if self.usernameRegister and self.passwordRegister and self.selectedQuestionRegister and self.selectedQuestionAnswerRegister:
            if re.search(self.patternUsername, self.usernameRegister):
                if re.search(self.patternPassword, self.passwordRegister):
                    if self.selectedQuestionRegister != "Forgot Question":
                        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameRegister}", None)

                        if self.gotUserData is None:
                            self.userData = {
                                'Username': self.usernameRegister,
                                'Password': self.passwordRegister,
                                'Question': self.selectedQuestionRegister,
                                self.selectedQuestionRegister: self.selectedQuestionAnswerRegister,
                                'Remember': False,
                                'Status': True,
                                'Admin': False,
                                'LoggedIn': False
                                }

                            self.userLogData = {
                                'Status': True
                            }

                            self.userHistoryData = {
                                'Status': True
                            }

                            if self.userDatabase.post(f"/filemanager-2febc-default-rtdb:/{self.usernameRegister}", self.userData) is not None:
                                if self.userDatabase.post(f"/filemanager-2febc-default-rtdb:/{self.usernameRegister}", self.userLogData) is not None:
                                    if self.userDatabase.post(f"/filemanager-2febc-default-rtdb:/{self.usernameRegister}", self.userHistoryData) is not None:
                                        if messagebox.showinfo("Success", "Registration successful."):
                                            self.usernameEntry_2.delete(0, END)
                                            self.passwordEntry_2.delete(0, END)
                                            self.questionsCombobox_1.current(0)
                                            self.answerEntry_1.delete(0, END)

                                            self.registerUserLogFile()
                                            self.setLoginFrame()

                            else:
                                if messagebox.showerror("Error", "Unexpected error."):
                                    self.usernameEntry_2.delete(0, END)
                                    self.passwordEntry_2.delete(0, END)
                                    self.questionsCombobox_1.current(0)
                                    self.answerEntry_1.delete(0, END)

                                    self.usernameEntry_2.focus_set()

                        else:
                            if messagebox.showwarning("Warning", "User already exits."):
                                self.usernameEntry_2.delete(0, END)
                                self.passwordEntry_2.delete(0, END)
                                self.questionsCombobox_1.current(0)
                                self.answerEntry_1.delete(0, END)

                                self.usernameEntry_2.focus_set()

                    else:
                        if messagebox.showwarning("Warning", "Choose another question."):
                            self.usernameEntry_2.delete(0, END)
                            self.passwordEntry_2.delete(0, END)
                            self.questionsCombobox_1.current(0)
                            self.answerEntry_1.delete(0, END)

                            self.usernameEntry_2.focus_set()

                else:
                    if messagebox.showwarning("Warning", "Invalid password."):
                        self.usernameEntry_2.delete(0, END)
                        self.passwordEntry_2.delete(0, END)
                        self.questionsCombobox_1.current(0)
                        self.answerEntry_1.delete(0, END)

                        self.usernameEntry_2.focus_set()

            else:
                if messagebox.showwarning("Warning", "Invalid username."):
                    self.usernameEntry_2.delete(0, END)
                    self.passwordEntry_2.delete(0, END)
                    self.questionsCombobox_1.current(0)
                    self.answerEntry_1.delete(0, END)

                    self.usernameEntry_2.focus_set()

        else:
            if messagebox.showwarning("Warning", "All fields are required."):
                self.usernameEntry_2.delete(0, END)
                self.passwordEntry_2.delete(0, END)
                self.questionsCombobox_1.current(0)
                self.answerEntry_1.delete(0, END)

                self.usernameEntry_2.focus_set()

    def loginUser(self, event=None):
        self.usernameLogin = self.username_1.get()
        self.passwordLogin = self.password_1.get()
        self.rememberUser = self.isChecked_1.get()

        if self.usernameLogin and self.passwordLogin:
            if re.search(self.patternUsername, self.usernameLogin):
                if re.search(self.patternPassword, self.passwordLogin):
                    self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)

                    if self.gotUserData is not None:
                        self.userDataKey = list(self.gotUserData.keys())[0]
                        self.gotUserData = list(self.gotUserData.values())[0]

                        if self.gotUserData.get("Password") == self.passwordLogin:
                            self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", "Remember", self.rememberUser)
                            self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", "LoggedIn", True)

                            if self.gotUserData.get("Status"):
                                if not self.gotUserData.get("Admin"):
                                    if messagebox.showinfo("Success", "Login successful."):
                                        self.usernameEntry_1.delete(0, END)
                                        self.passwordEntry_1.delete(0, END)
                                        self.isChecked_1.set(False)

                                        self.loginUserLogFile()
                                        self.setOrganizerFrames()

                                else:
                                    self.loginUserLogFile()
                                    self.setAdminPanelFrames()

                            else:
                                if messagebox.showerror("Error", "Contact with your administrator."):
                                    self.usernameEntry_1.delete(0, END)
                                    self.passwordEntry_1.delete(0, END)
                                    self.isChecked_1.set(False)

                                    self.usernameEntry_1.focus_set()

                        else:
                            if messagebox.showwarning("Warning", "Incorrect password."):
                                self.usernameEntry_1.delete(0, END)
                                self.passwordEntry_1.delete(0, END)
                                self.isChecked_1.set(False)

                                self.usernameEntry_1.focus_set()

                    else:
                        if messagebox.askquestion("Question", "Do you want to register?"):
                            self.usernameEntry_1.delete(0, END)
                            self.passwordEntry_1.delete(0, END)
                            self.isChecked_1.set(False)

                            self.usernameEntry_1.focus_set()

                            self.setSignupFrame()

                else:
                    if messagebox.showwarning("Warning", "Invalid Password."):
                        self.usernameEntry_1.delete(0, END)
                        self.passwordEntry_1.delete(0, END)
                        self.isChecked_1.set(False)

                        self.usernameEntry_1.focus_set()

            else:
                if messagebox.showwarning("Warning", "Invalid username."):
                    self.usernameEntry_1.delete(0, END)
                    self.passwordEntry_1.delete(0, END)
                    self.isChecked_1.set(False)

                    self.usernameEntry_1.focus_set()

        else:
            if messagebox.showwarning("Warning", "All fields are required."):
                self.usernameEntry_1.delete(0, END)
                self.passwordEntry_1.delete(0, END)
                self.isChecked_1.set(False)

                self.usernameEntry_1.focus_set()

    def getPassword(self, event=None):
        self.usernameForgot = self.username_3.get()
        self.questionForgot = self.selectedQuestion_2.get()
        self.answerForgot = self.selectedQuestionAnswer_2.get()

        if self.usernameForgot and self.questionForgot and self.answerForgot:
            if re.search(self.patternUsername, self.usernameForgot):
                self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameForgot}", None)

                if self.gotUserData is not None:
                    self.gotUserData = list(self.gotUserData.values())[0]

                    if self.gotUserData.get("Question") == self.questionForgot:
                        if self.gotUserData.get(self.questionForgot) == self.answerForgot:
                            self.gotUserPassword = f"Your Password : {self.gotUserData.get('Password')}"

                            if messagebox.showinfo("Success", self.gotUserPassword):
                                self.usernameEntry_3.delete(0, END)
                                self.answerEntry_2.delete(0, END)
                                self.questionsCombobox_2.current(0)

                                self.setLoginFrame()

                        else:
                            if messagebox.showwarning("Warning", "Incorrect answer"):
                                self.usernameEntry_3.delete(0, END)
                                self.answerEntry_2.delete(0, END)
                                self.questionsCombobox_2.current(0)

                                self.usernameEntry_3.focus_set()

                    else:
                        if messagebox.showwarning("Warning", "Question not registered."):
                            self.usernameEntry_3.delete(0, END)
                            self.answerEntry_2.delete(0, END)
                            self.questionsCombobox_2.current(0)

                            self.usernameEntry_3.focus_set()

                else:
                    if messagebox.showwarning("Warning", "User not found."):
                        self.usernameEntry_3.delete(0, END)
                        self.answerEntry_2.delete(0, END)
                        self.questionsCombobox_2.current(0)

                        self.usernameEntry_3.focus_set()

            else:
                if messagebox.showwarning("Warning", "Invalid username."):
                    self.usernameEntry_3.delete(0, END)
                    self.answerEntry_2.delete(0, END)
                    self.questionsCombobox_2.current(0)

                    self.usernameEntry_3.focus_set()

        else:
            if messagebox.showwarning("Warning", "All fields are required."):
                self.usernameEntry_3.delete(0, END)
                self.answerEntry_2.delete(0, END)
                self.questionsCombobox_2.current(0)

                self.usernameEntry_3.focus_set()

    def autoFillPassword(self, event):
        self.usernameLogin = self.username_1.get()
        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)

        if self.gotUserData is not None:
            self.gotUserData = list(self.gotUserData.values())[0]

            if self.gotUserData.get("Remember"):
                self.savedPassword = self.gotUserData.get("Password")
                self.passwordEntry_1.insert(0, self.savedPassword)
                self.rememberCheck_1.select()

        else:
            self.passwordEntry_1.focus_set()

    def changePassword(self, event=None):
        self.oldPassword_2 = self.oldPassword_1.get()
        self.newPassword_2 = self.newPassword_1.get()
        self.confirmPassword_2 = self.confirmPassword_1.get()

        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)

        self.userDataKey = list(self.gotUserData.keys())[0]
        self.gotUserData = list(self.gotUserData.values())[0]

        if self.oldPassword_2 and self.newPassword_2 and self.confirmPassword_2:
            if self.newPassword_2 == self.confirmPassword_2:
                if self.gotUserData.get("Password") == self.oldPassword_2:
                    self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", "Password", self.newPassword_2)
                    self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", "Remember", False)

                    if messagebox.showinfo("Success", "Your password has been changed."):
                        self.oldPasswordEntry_1.delete(0, END)
                        self.newPasswordEntry_1.delete(0, END)
                        self.confirmPasswordEntry_1.delete(0, END)

                        self.oldPasswordEntry_1.focus_set()

                        self.changePasswordLogFile()
                        self.isChecked_1.set(False)
                        self.setMainFrames()

                else:
                    if messagebox.showwarning("Warning", "Incorrect Password."):
                        self.oldPasswordEntry_1.delete(0, END)
                        self.newPasswordEntry_1.delete(0, END)
                        self.confirmPasswordEntry_1.delete(0, END)

                        self.oldPasswordEntry_1.focus_set()

            else:
                if messagebox.showwarning("Warning", "Password doesn't match."):
                    self.oldPasswordEntry_1.delete(0, END)
                    self.newPasswordEntry_1.delete(0, END)
                    self.confirmPasswordEntry_1.delete(0, END)

                    self.oldPasswordEntry_1.focus_set()

        else:
            if messagebox.showwarning("Warning", "All fields are required."):
                self.oldPasswordEntry_1.delete(0, END)
                self.newPasswordEntry_1.delete(0, END)
                self.confirmPasswordEntry_1.delete(0, END)

                self.oldPasswordEntry_1.focus_set()

    def validateFolderPath(self, event=None):
        self.folderPath_2 = self.folderPath_1.get()

        if self.folderPath_2.strip():
            if os.path.exists(self.folderPath_2):
                self.setChooseFilesFrame()

            else:
                if messagebox.showwarning("Warning", "Path doesn't exists."):
                    self.folderPathEntry_1.delete(0, END)

        else:
            if messagebox.showwarning("Warning", "Please enter valid path."):
                self.folderPathEntry_1.delete(0, END)

    def selectAll(self):
        self.setCheckValue = self.setCheckValue ^ True

        for self.var in self.varList:
            self.var.set(self.setCheckValue)
    
    def selectAllUsersByAdmin(self):
        self.setCheckValue = self.setCheckValue ^ True

        for self.userCheck in self.checkUsersList:
            self.userCheck.set(self.setCheckValue)

    def deleteHistory(self):
        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)
        self.userDataKey = list(self.gotUserData.keys())[2]

        if self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", None):
            self.userHistoryDict = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", None)

            if messagebox.askyesno("Warning", "Do you want to delete history?"):
                self.historyListbox_1.delete(0, END)

                for self.key in self.userHistoryDict:
                    if self.key != "Status":
                        self.userDatabase.delete(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", self.key)

        else:
            messagebox.showwarning("Warning", "Already empty.")

    def deleteAccount(self):
        if messagebox.askyesno("Delete Account", "Do you want to delete your account?"):
            self.userDatabase.delete("/filemanager-2febc-default-rtdb:/", self.usernameLogin)

            if messagebox.showinfo("Success", "Account successfully deleted."):
                self.setMainFrames()

    def deleteUserByAdmin(self):
        self.checkedUsers = []

        for self.userCheck in self.checkUsersList:
            self.checkedUsers.append(self.userCheck.get())

        self.selectedUsers = []

        for self.checked in range(len(self.checkedUsers)):
            if self.checkedUsers[self.checked]:
                self.selectedUsers.append(self.nonAdminUsers[self.checked])

        for self.userDelete in self.selectedUsers:
            self.userDatabase.delete(f"/filemanager-2febc-default-rtdb:/", self.userDelete)

        if messagebox.showinfo("Success", "Users has been successfully deleted."):
            self.adminListBox_3.delete(0, END)
            self.setDeleteUserByAdminFrame()

    @staticmethod
    def file_finder(path, extensions):
        return [file for file in os.listdir(path) for extension in extensions if file.endswith(extension)]

    def organizeFiles(self, event=None):
        self.checkedFiles = []

        for self.var in self.varList:
            self.checkedFiles.append(self.var.get())

        self.extensionList = list(self.extensions_dictionary.keys())
        self.selectedExtensions = []

        for self.checked in range(len(self.checkedFiles)):
            if self.checkedFiles[self.checked]:
                self.selectedExtensions.append(self.extensionList[self.checked])

        self.saveUserHistory()

        self.status = 0

        for self.extension_type, self.extension_tuple in self.extensions_dictionary.items():
            if self.extension_type in self.selectedExtensions:
                self.folderName = self.extension_type.split('_')[0].title() + ' Files'
                self.fullPath = os.path.join(self.folderPath_2, self.folderName)

                self.filesList = self.file_finder(self.folderPath_2, self.extension_tuple)

                if self.filesList:
                    for self.item in (self.filesList):
                        self.itemFullPath = os.path.join(self.folderPath_2, self.item)
                        self.itemNewFullPath = os.path.join(self.fullPath, self.item)

                        if not os.path.exists(self.fullPath):
                            os.mkdir(self.fullPath)

                        shutil.move(self.itemFullPath, self.itemNewFullPath)

                        self.status += 1

        else:
            if self.status > 0:
                if messagebox.showinfo("Success", "Files are organized."):
                    self.folderPathEntry_1.delete(0, END)

                    for self.var in self.varList:
                        self.var.set(False)

                    self.setOrganizerLeftFrame()

            else:
                if messagebox.showinfo("Info", "Already organized."):
                    self.folderPathEntry_1.delete(0, END)

                    for self.var in self.varList:
                        self.var.set(False)

                    self.setOrganizerLeftFrame()

    def saveUserHistory(self):
        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)
        self.currentTime = datetime.now().strftime("%d-%b-%y %I:%M:%S")
        self.userDataKey = list(self.gotUserData.keys())[2]
        self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", self.currentTime, self.folderPath_2)
    
    def saveUserDataValues(self):
        self.adminCheckVar_2 = self.adminCheckVar_1.get()
        self.statusCheckVar_2 = self.statusCheckVar_1.get()

        self.getUserFullInfo = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.selectedUserByAdmin}", None)
        self.getUserDataKey = list(self.getUserFullInfo.keys())[0]

        self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.selectedUserByAdmin}/{self.getUserDataKey}", "Admin", self.adminCheckVar_2)
        self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.selectedUserByAdmin}/{self.getUserDataKey}", "Status", self.statusCheckVar_2)

    def registerUserLogFile(self):
        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameRegister}", None)
        self.currentTime = datetime.now().strftime("%d-%b-%y %I:%M:%S")
        self.userDataKey = list(self.gotUserData.keys())[1]
        self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameRegister}/{self.userDataKey}/", self.currentTime, f"{self.usernameRegister} has been registered.")

    def loginUserLogFile(self):
        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)
        self.currentTime = datetime.now().strftime("%d-%b-%y %I:%M:%S")
        self.userDataKey = list(self.gotUserData.keys())[1]
        self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", self.currentTime, f"{self.usernameLogin} has been logged in.")

    def changePasswordLogFile(self):
        self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)
        self.currentTime = datetime.now().strftime("%d-%b-%y %I:%M:%S")
        self.userDataKey = list(self.gotUserData.keys())[1]
        self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey}/", self.currentTime, f"{self.usernameLogin} has changed password.")

    @staticmethod
    def onEnter(event):
        event.widget.configure(bd=2)

        if isinstance(event.widget, Entry):
            event.widget.focus_set()

    @staticmethod
    def onLeave(event):
        event.widget.configure(bd=0)

    @staticmethod
    def openFacebook():
        webbrowser.open("https://www.facebook.com//")
    
    @staticmethod
    def openTwitter():
        webbrowser.open("https://www.twitter.com//")
    
    @staticmethod
    def openYoutube():
        webbrowser.open("https://www.youtube.com//")
    
    @staticmethod
    def openInstagram():
        webbrowser.open("https://www.instagram.com//")

    def logoutUser(self):
        try:
            self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)
            self.userKey_0 = list(self.gotUserData.keys())[0]
            self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userKey_0 }", None)
            
            if self.gotUserData.get("LoggedIn"):
                if messagebox.askyesno("Logout", "Do you want to logout?"):
                    self.gotUserData = self.userDatabase.get(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}", None)
                    self.currentTime = datetime.now().strftime("%d-%b-%y %I:%M:%S")

                    self.userDataKey_0 = list(self.gotUserData.keys())[0]
                    self.userDataKey_1 = list(self.gotUserData.keys())[1]

                    self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey_0}/", "LoggedIn", False)
                    self.userDatabase.put(f"/filemanager-2febc-default-rtdb:/{self.usernameLogin}/{self.userDataKey_1}/", self.currentTime, f"{self.usernameLogin} has been logged out.")

                    self.usernameEntry_1.delete(0, END)
                    self.passwordEntry_1.delete(0, END)
                    self.isChecked_1.set(False)
                    self.setMainFrames()
        
        except Exception:
            self.screen.destroy()
            sys.exit()

    def closeScreen(self):
        try:
            if messagebox.askyesnocancel("Close", "Do you want to close?"):
                self.logoutUser()
                self.screen.destroy()
                sys.exit()
        
        except Exception as e:
            print("hello")


if __name__ == '__main__':
    organizer = FileOrganizer()
