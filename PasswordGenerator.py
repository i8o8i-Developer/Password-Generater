# Import Necessary Libraries
import hashlib
import secrets
import string
import datetime
import time
import json
import os
import getpass
from Crypto.Cipher import AES
import bcrypt

# Define A Class For The PasswordGenerator
class PasswordGenerator:
    def __init__(self):
        # Get User's Name For Personalized Greetings
        self.UserName = input("👋 Hello There! What's Your Name? ")
        # Generate A Greeting Message Based On Current Time, Date, And Day
        self.Greeting = self.GetGreeting()
        # Initialize An Empty List To Store Saved Passwords
        self.Passwords = []
        # File To Store Encrypted Passwords
        self.PasswordFile = "passwords.enc"
        # Setup Master Password And Encryption Key
        self.SetupMasterPassword()

    # Generate A Personalized Greeting Message
    def GetGreeting(self):
        CurrentTime = datetime.datetime.now().strftime("%I:%M %p")
        CurrentDate = datetime.datetime.now().strftime("%B %d, %Y")
        CurrentDay = datetime.datetime.now().strftime("%A")
        return f"🌞 Good Day, {self.UserName}! It's {CurrentTime} On {CurrentDate}, {CurrentDay}."

    # Setup Master Password For Encryption
    def SetupMasterPassword(self):
        KeyFile = "Master.key"
        if os.path.exists(KeyFile):
            with open(KeyFile, "rb") as f:
                self.Key = f.read()
        else:
            MasterPassword = getpass.getpass("🔐 Set A Master Password For Encrypting Your Passwords: ")
            Salt = bcrypt.gensalt()
            Hashed = bcrypt.hashpw(MasterPassword.encode(), Salt)
            self.Key = hashlib.sha256(MasterPassword.encode()).digest()
            with open(KeyFile, "wb") as f:
                f.write(self.Key)
            with open("Master.hash", "wb") as f:
                f.write(Hashed)
        self.LoadPasswords()

    # Load Encrypted Passwords From File
    def LoadPasswords(self):
        if os.path.exists(self.PasswordFile):
            with open(self.PasswordFile, "rb") as f:
                Nonce = f.read(16)
                Tag = f.read(16)
                Ciphertext = f.read()
            Cipher = AES.new(self.Key, AES.MODE_EAX, nonce=Nonce)
            try:
                DecryptedData = Cipher.decrypt_and_verify(Ciphertext, Tag).decode()
                self.Passwords = json.loads(DecryptedData)
            except:
                print("❌ Failed To Decrypt Passwords. Wrong Master Password Or Corrupted File.")
                self.Passwords = []

    # Function To Generate A Password Using Provided Characters And Length
    def GeneratePassword(self, Length, Characters):
        return ''.join(secrets.choice(Characters) for _ in range(Length))

    # Generate A Numeric Password
    def GenerateNumericPassword(self, Length):
        return self.GeneratePassword(Length, string.digits)

    # Generate An Alphanumeric Password
    def GenerateAlphanumericPassword(self, Length):
        return self.GeneratePassword(Length, string.ascii_letters + string.digits)

    # Generate A Password With Special Characters
    def GenerateSpecialPassword(self, Length):
        return self.GeneratePassword(Length, string.ascii_letters + string.digits + string.punctuation)

    # Generate A Custom Password Using A Name And Random Numeric
    def GenerateCustomPassword(self, Name, Length):
        MaxNameLength = Length - 4
        TruncatedName = Name[:MaxNameLength]
        RandomNumeric = self.GenerateNumericPassword(Length - len(TruncatedName))
        return f"{TruncatedName}{RandomNumeric}"

    # Generate A Passphrase
    def GeneratePassphrase(self, NumWords=4, Separator="-"):
        WordList = [
            "apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "honeydew",
            "kiwi", "lemon", "mango", "nectarine", "orange", "peach", "quince", "raspberry",
            "strawberry", "tangerine", "ugli", "vanilla", "watermelon", "xigua", "yam", "zucchini"
        ]
        Words = [secrets.choice(WordList) for _ in range(NumWords)]
        return Separator.join(Words)

    # Hash A Given Password Using SHA-256 Algorithm
    def HashPassword(self, Password):
        Sha256Hash = hashlib.sha256(Password.encode()).hexdigest()
        return Sha256Hash

    # Save A Password To The List Of Saved Passwords
    def SaveToFile(self, Password, WebsiteName):
        Timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.Passwords.append({
            "timestamp": Timestamp,
            "website_name": WebsiteName,
            "password": Password
        })
        self.SavePasswordsToFile()

    # Save Passwords To Encrypted File
    def SavePasswordsToFile(self):
        Data = json.dumps(self.Passwords)
        Cipher = AES.new(self.Key, AES.MODE_EAX)
        Ciphertext, Tag = Cipher.encrypt_and_digest(Data.encode())
        with open(self.PasswordFile, "wb") as f:
            f.write(Cipher.nonce)
            f.write(Tag)
            f.write(Ciphertext)

    # Display The List Of Saved Passwords With Details
    def DisplaySavedPasswords(self):
        print("\n🔐 Saved Passwords:")
        for i, Password in enumerate(self.Passwords):
            print(f"{i+1}. 📅 Timestamp: {Password['timestamp']}")
            print(f"   🌐 Website/Application: {Password['website_name']}")
            print(f"   🔑 Password: {Password['password']}")
            print("-" * 40)

    # Search For Passwords By Website Name
    def SearchPasswords(self, Query):
        Results = [p for p in self.Passwords if Query.lower() in p['website_name'].lower()]
        if Results:
            print(f"\n🔍 Search Results For '{Query}':")
            for i, Password in enumerate(Results):
                print(f"{i+1}. 📅 Timestamp: {Password['timestamp']}")
                print(f"   🌐 Website/Application: {Password['website_name']}")
                print(f"   🔑 Password: {Password['password']}")
                print("-" * 40)
        else:
            print(f"❌ No Passwords Found For '{Query}'.")

    # Delete A Password By Index
    def DeletePassword(self, Index):
        if 0 <= Index < len(self.Passwords):
            Deleted = self.Passwords.pop(Index)
            self.SavePasswordsToFile()
            print(f"🗑️ Deleted Password For {Deleted['website_name']}.")
        else:
            print("❌ Invalid Index.")

    # Export Passwords To CSV
    def ExportPasswords(self, Filename="Passwords.csv"):
        import csv
        with open(Filename, "w", newline="") as f:
            Writer = csv.writer(f)
            Writer.writerow(["Timestamp", "Website", "Password"])
            for p in self.Passwords:
                Writer.writerow([p["timestamp"], p["website_name"], p["password"]])
        print(f"📄 Passwords Exported To {Filename}.")

    # Evaluate The Strength Of A Password And Return A Complexity Level
    def EvaluatePasswordStrength(self, Password):
        Score = 0
        if len(Password) >= 8:
            Score += 1
        if len(Password) >= 12:
            Score += 1
        if any(c.islower() for c in Password):
            Score += 1
        if any(c.isupper() for c in Password):
            Score += 1
        if any(c.isdigit() for c in Password):
            Score += 1
        if any(c in string.punctuation for c in Password):
            Score += 1
        # Check For Common Patterns
        if Password.lower() in ['password', '123456', 'qwerty']:
            Score = 0
        if Score <= 2:
            return "Weak"
        elif Score <= 4:
            return "Medium"
        else:
            return "Strong"

    # Copy Text To Clipboard (Requires Pyperclip Module)
    def CopyToClipboard(self, Text):
        try:
            import pyperclip
            pyperclip.copy(Text)
            print("📋 Password Copied To Clipboard!")
        except ImportError:
            print("❌ Clipboard Integration Is Not Supported On Your System.")

    # Main Function To Run The Password Generator Program
    def Main(self):
        print(self.Greeting)
        print("🚀 Welcome To The Most Advanced Password Generator Program")
        print("🔐 Created By i8o8i Developer\n")

        while True:
            # Get The Name Of The Website Or Application
            WebsiteName = input("\n🌐 Enter The Name Of The Website Or Application For Which You Want To Create A Super-Secure Password: ")
            print("\n🚀 Generating A Password For:", WebsiteName)

            print("\n🛠 Choose The Password Type:")
            print("1. Numeric Only")
            print("2. Alphanumeric")
            print("3. Alphanumeric + Special Characters")
            print("4. Custom Password (Desired Name + Numeric)")
            print("5. Passphrase")
            print("6. Display Saved Passwords")
            print("7. Search Passwords")
            print("8. Delete Password")
            print("9. Export Passwords")
            print("10. Pronounceable Password")
            print("11. Password with Specific Requirements")
            print("12. Bulk Generate Passwords")
            print("13. Calculate Password Entropy")
            print("14. Import Passwords from CSV")
            print("15. Show Password Aging")
            print("16. Exit")

            try:
                Option = int(input("🔢 Enter Your Choice : "))

                if Option == 16:
                    print("🚀 Exiting Program...")
                    time.sleep(2)
                    print("")
                    print("🌟 Have An Amazing Day Ahead!")
                    time.sleep(10)
                    break
                elif Option < 1 or Option > 16:
                    print("❌ Invalid Option. Please Enter A Valid Choice.")
                    continue

                if Option in [1,2,3,4]:
                    PasswordLength = int(input("🔑 Enter The Desired Password Length: "))

                if Option == 1:
                    Password = self.GenerateNumericPassword(PasswordLength)
                elif Option == 2:
                    Password = self.GenerateAlphanumericPassword(PasswordLength)
                elif Option == 3:
                    Password = self.GenerateSpecialPassword(PasswordLength)
                elif Option == 4:
                    DesiredName = input("📛 Enter A Desired Name/Word: ")
                    if len(DesiredName) >= PasswordLength - 4:
                        print("❌ Desired Name/Word Is Too Long For This Password Length.")
                        continue
                    Password = self.GenerateCustomPassword(DesiredName, PasswordLength)
                elif Option == 5:
                    NumWords = int(input("🔢 Enter Number Of Words For Passphrase (Default 4): ") or 4)
                    Separator = input("🔗 Enter Separator (Default -): ") or "-"
                    Password = self.GeneratePassphrase(NumWords, Separator)
                elif Option == 6:
                    self.DisplaySavedPasswords()
                    continue
                elif Option == 7:
                    Query = input("🔍 Enter Website Name To Search: ")
                    self.SearchPasswords(Query)
                    continue
                elif Option == 8:
                    self.DisplaySavedPasswords()
                    try:
                        Index = int(input("🗑️ Enter The Number Of The Password To Delete: ")) - 1
                        self.DeletePassword(Index)
                    except ValueError:
                        print("❌ Invalid Number.")
                    continue
                elif Option == 9:
                    Filename = input("📄 Enter Filename For Export (Default Passwords.Csv): ") or "Passwords.csv"
                    self.ExportPasswords(Filename)
                    continue
                elif Option == 10:
                    PasswordLength = int(input("🔑 Enter The Desired Password Length: "))
                    Password = self.GeneratePronounceablePassword(PasswordLength)
                elif Option == 11:
                    PasswordLength = int(input("🔑 Enter The Desired Password Length: "))
                    upper = input("Include Uppercase? (y/n): ").lower() == 'y'
                    lower = input("Include Lowercase? (y/n): ").lower() == 'y'
                    digits = input("Include Digits? (y/n): ").lower() == 'y'
                    symbols = input("Include Symbols? (y/n): ").lower() == 'y'
                    Password = self.GeneratePasswordWithRequirements(PasswordLength, upper, lower, digits, symbols)
                elif Option == 12:
                    count = int(input("🔢 Enter Number Of Passwords: "))
                    print("Type:")
                    print("1. Numeric")
                    print("2. Alphanumeric")
                    print("3. Special")
                    print("4. Pronounceable")
                    type = int(input("Choose type: "))
                    length = int(input("🔑 Length: "))
                    passwords = self.BulkGenerate(count, type, length)
                    print("\n🔐 Generated Passwords:")
                    for p in passwords:
                        print(p)
                    continue
                elif Option == 13:
                    pwd = input("Enter Password To Check Entropy: ")
                    entropy = self.CalculateEntropy(pwd)
                    print(f"🔢 Entropy: {entropy} bits")
                    continue
                elif Option == 14:
                    filename = input("📄 Enter CSV Filename To Import: ")
                    self.ImportPasswords(filename)
                    continue
                elif Option == 15:
                    self.ShowPasswordAging()
                    continue

                print("\n🔐 Password Generated For:", WebsiteName)
                print("🔒 Generated Password:", Password)
                Strength = self.EvaluatePasswordStrength(Password)
                print("🌟 Password Strength:", Strength)
                entropy = self.CalculateEntropy(Password)
                print("🔢 Password Entropy:", entropy, "bits")

                if Strength == "Weak":
                    print("🔴 This Password Is Weak. Make It Stronger!")
                elif Strength == "Medium":
                    print("🟡 This Password Is Of Intermediate Strength.")
                else:
                    print("🟢 This Password Is Strong And Secure!")

                HashedPassword = self.HashPassword(Password)
                print("🔑 Hashed Password:", HashedPassword)

                SaveChoice = input("💾 Do You Want To Save This Password? (Yes/No): ").lower()
                if SaveChoice == "yes":
                    self.SaveToFile(Password, WebsiteName)
                    print("📝 Password Saved.")

                ClipboardChoice = input("📋 Do You Want To Copy The Password To Clipboard? (Yes/No): ").lower()
                if ClipboardChoice == "yes":
                    self.CopyToClipboard(Password)

            except ValueError:
                print("❌ Invalid Input. Please Enter A Valid Option Or Value.")

# Run The Program If Executed As A Standalone Script
if __name__ == "__main__":
    Generator = PasswordGenerator()
    Generator.Main()