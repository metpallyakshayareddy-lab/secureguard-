# ============================================================
# train.py – Train & Save ML Models Using scikit-learn
#
# HOW TO RUN:
#   python train.py
#
# This script:
#   1. Generates synthetic training data (phishing + safe samples)
#   2. Trains a Random Forest model for URL detection
#   3. Trains a Logistic Regression + TF-IDF model for Email detection
#   4. Saves both models to disk as .pkl files
# ============================================================

import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from features import extract_url_features


# ============================================================
# 1. URL TRAINING DATA
# ============================================================

PHISHING_URLS = [
    # --- Suspicious TLDs (.tk, .ml, .ga, .cf, .xyz, etc.) ---
    "http://paypa1-secure.login.tk/verify/account",
    "http://secure-account-update.ml/signin",
    "https://www.paypal.com.secure-verify.ga/",
    "http://amazon-billing.suspended.xyz/update",
    "http://apple-id.verify.account.cf/confirm",
    "http://login.microsoft-account.tk/verify",
    "http://netflix.com.login.update.bid/",
    "http://secure.banking.verify.credential.tk/",
    "http://google.com.malicious.domain.ml/signin",
    "http://account.suspended.amazon.verify.xyz/",
    "http://update.your.paypal.bank.account.tk/",
    "http://login.facebook.com.verify.cf/",
    "http://chase.online.banking.verify.ml/login",
    "http://secure.appleid.apple.verify.ga/",
    "http://ebayisapi.dll.login.bid/verify",
    "http://webscr.paypal.phishing.cf/cmd=login",
    "http://signin.dropbox.account.update.ml/",
    "http://reset-password.microsoft-verify.tk/",
    "http://unusual.activity.detected.bank.ml/",
    "http://account.locked.verify.credentials.cf/",
    "http://billing.update.confirm.netflix.xyz/",
    "http://secure.payment.required.update.tk/",
    "http://verify.now.login.suspended.account.ml/",
    "http://free-prize.you-won.lottery.tk/claim",
    "http://your.account.compromised.secure.cf/",
    "http://malware.download.exe.xyz/file.exe",
    "http://suspicious-domain.webcam.phishing.ml/",
    "http://login.verify.bank.credentials.win/",
    "http://account-security.verify-now.tk/login",
    "http://paypal-limited.account-restore.ml/",

    # --- IP-address based (always suspicious) ---
    "http://192.168.1.1/login/bank",
    "http://192.0.2.1/phishing/paypal/login",
    "http://10.0.0.1/secure/account/verify",
    "http://172.16.0.1/banking/signin",
    "http://203.0.113.42/update/credentials",
    "http://198.51.100.7/login/facebook",
    "http://45.142.212.100/paypal/verify",
    "http://91.108.56.130/account/suspended",
    "http://77.247.110.1/banking/login",
    "http://5.196.73.132/microsoft/signin",

    # --- Typosquatting / look-alike domains ---
    "http://arnazon.com/signin",
    "http://paypa1.com/login",
    "http://micosoft.com/account/verify",
    "http://g00gle-security.com/account",
    "http://linkedln.com/login",
    "http://faceb00k.com/verify",
    "http://twtter.com/account/login",
    "http://app1e.com/id/verify",
    "http://netf1ix.com/account/update",
    "http://dropb0x.com/signin",
    "http://chasebank-secure.com/login",
    "http://bankofamerica-secure.net/verify",
    "http://wellsfarg0.com/online/banking",
    "http://citibank-online.secure-login.com/",
    "http://paypa1-secure.account-verify.com/login",

    # --- Keyword stuffing / credential harvesting ---
    "http://secure-login-verify-account.com/signin",
    "http://update-billing-information-now.net/",
    "http://confirm-your-password-now.org/reset",
    "http://verify-account-security.net/login",
    "http://signin-account-update-required.com/",
    "http://account-suspended-verify-now.net/",
    "http://banking-secure-login-update.com/",
    "http://credential-verify-now-secure.net/",
    "http://password-reset-required-secure.com/",
    "http://billing-update-required-netflix.net/",

    # --- Long suspicious URLs ---
    "http://www.secure-paypal-login-verify-account-suspended-update-credentials.com/signin?redirect=true&source=email",
    "http://amazon.account.security.update.billing.suspended.verify.login.confirm.tk/",
    "http://login-microsoft-account-verify-security-unusual-activity-now.ml/",
    "http://apple-id-account-suspended-verify-now-confirm-billing.xyz/account",

    # --- Mixed suspicious signals ---
    "http://paypal.verify-account.xyz/login?user=victim&redirect=home",
    "http://faceboook.secure-verify.tk/account/login",
    "http://amazon.support-secure.ml/order/hold/verify",
    "http://support.apple.com.verify-account.tk/",
    "http://accounts.google.com.phishing.xyz/signin",
    "http://secure.chase.bank-login.xyz/verify",
    "http://microsoft-account-alert.secure-login.ml/",
    "http://dropbox-storage-full-update-billing.cf/login",
]

SAFE_URLS = [
    # --- Major websites ---
    "https://www.google.com",
    "https://www.amazon.com/products",
    "https://github.com/user/repo",
    "https://stackoverflow.com/questions",
    "https://en.wikipedia.org/wiki/Python",
    "https://www.youtube.com/watch?v=abc123",
    "https://www.linkedin.com/in/profile",
    "https://docs.python.org/3/library",
    "https://www.bbc.com/news",
    "https://www.reddit.com/r/programming",
    "https://www.microsoft.com/en-us/windows",
    "https://support.apple.com/en-us",
    "https://www.netflix.com/browse",
    "https://mail.google.com/mail/u/0/",
    "https://drive.google.com/drive/my-drive",
    "https://www.facebook.com/home",
    "https://twitter.com/home",
    "https://www.instagram.com/explore",
    "https://www.dropbox.com/home",
    "https://www.paypal.com/us/home",
    "https://www.ebay.com/sch/i.html",
    "https://www.chase.com/personal/banking",
    "https://outlook.live.com/mail/inbox",
    "https://www.airbnb.com/rooms",
    "https://www.booking.com/hotels",
    "https://www.coursera.org/courses",
    "https://www.udemy.com/courses/development",
    "https://medium.com/programming",
    "https://www.nytimes.com/section/technology",
    "https://www.forbes.com/technology",

    # --- Developer / tech sites ---
    "https://developer.mozilla.org/en-US/docs",
    "https://docs.microsoft.com/en-us/azure",
    "https://cloud.google.com/products",
    "https://aws.amazon.com/s3/",
    "https://hub.docker.com/explore",
    "https://pypi.org/project/requests/",
    "https://npmjs.com/package/lodash",
    "https://reactjs.org/docs/getting-started.html",
    "https://vuejs.org/guide/introduction.html",
    "https://angular.io/start",

    # --- News & media ---
    "https://www.cnn.com/world",
    "https://www.theguardian.com/technology",
    "https://techcrunch.com/startups/",
    "https://www.wired.com/category/science/",
    "https://arstechnica.com/gadgets/",
    "https://www.reuters.com/technology/",
    "https://www.bloomberg.com/technology",

    # --- E-commerce ---
    "https://www.etsy.com/shop/handmade",
    "https://www.walmart.com/grocery",
    "https://www.bestbuy.com/laptops",
    "https://www.target.com/deals",
    "https://shopify.com/pricing",

    # --- Education ---
    "https://www.khanacademy.org/math",
    "https://edx.org/learn/python",
    "https://www.pluralsight.com/courses",
    "https://freecodecamp.org/learn",
    "https://www.codecademy.com/learn",

    # --- Social / communication ---
    "https://discord.com/channels/@me",
    "https://slack.com/intl/en-gb/",
    "https://zoom.us/meeting",
    "https://teams.microsoft.com/",
    "https://meet.google.com/",

    # --- Finance (legit) ---
    "https://www.fidelity.com/investing/stocks",
    "https://robinhood.com/stocks",
    "https://www.coinbase.com/trade",
    "https://finance.yahoo.com/",
    "https://www.bankofamerica.com/deposits/",

    # --- Government / official ---
    "https://www.irs.gov/filing",
    "https://www.usa.gov/federal-agencies",
    "https://www.nhs.uk/conditions",
    "https://www.gov.uk/browse",
]


def build_url_dataset():
    X, y = [], []
    for url in PHISHING_URLS:
        X.append(extract_url_features(url))
        y.append(1)   # 1 = phishing
    for url in SAFE_URLS:
        X.append(extract_url_features(url))
        y.append(0)   # 0 = safe
    return X, y


# ============================================================
# 2. EMAIL TRAINING DATA (raw text — uses TF-IDF)
# ============================================================

PHISHING_EMAILS = [
    # --- Account suspension / credential theft ---
    "URGENT: Your bank account has been suspended. Click here to verify your password immediately.",
    "Dear Customer, Unusual activity detected. Confirm your credit card number to restore access.",
    "Final notice: Your PayPal account will be closed. Verify your account details immediately.",
    "Security Alert: Your Apple ID has been compromised. Reset your password now.",
    "Dear User, We detected suspicious login. Provide your social security number to verify.",
    "ACTION REQUIRED: Update your billing information or your Netflix account will be terminated!",
    "URGENT: Your email account will expire. Login immediately to avoid account suspension.",
    "Dear Account Holder, verify your bank account number to continue using our services.",
    "LAST CHANCE: Your account has been locked. Enter your CVV and PIN to unlock it.",
    "Microsoft Security Team: Unusual sign-in detected. Validate your password right now.",
    "IMPORTANT: Facebook detected unauthorized login. Confirm your password immediately!",
    "Dropbox: Your storage is full. Click link below to update your billing and payment info.",
    "FINAL NOTICE: Your credit card has been suspended. Call us now with your CVV number.",
    "Dear Customer, confirm your credentials to avoid account termination. Act now!",
    "Your Amazon account has been locked due to unusual activity. Verify your identity now.",
    "Your Chase Bank account is on hold. Click below to verify your social security number.",
    "Apple ID Alert: Your account has been disabled. Confirm billing details immediately.",
    "Netflix: Payment failed. Update your credit card information now to avoid cancellation.",
    "Dear valued customer, your account will be suspended in 24 hours. Verify your password.",
    "SECURITY ALERT: We detected a login from an unknown device. Confirm your password now.",

    # --- Lottery / prize / inheritance scams ---
    "You have won a lottery prize of $10,000! Claim your reward now by clicking the link.",
    "Congratulations! You are selected as lucky winner. Wire transfer required to claim inheritance.",
    "Dear Member, unclaimed funds of $5000 await. Provide date of birth to claim prize.",
    "You have won a $50,000 cash prize! Enter your bank account number to receive your money.",
    "Nigerian Prince inheritance: I need your bank account number to transfer $2 million.",
    "CONGRATULATIONS! Your email was randomly selected. Claim your $25,000 prize now!",
    "You are our lucky winner this month! Wire transfer of $15,000 awaits - claim today!",
    "Lottery Commission: You've won! Send your full name, address, and bank details to collect.",
    "Unclaimed inheritance of $3.5 million. You are the next of kin. Contact us urgently.",
    "Your email has won the International Sweepstakes. Claim your $100,000 prize immediately!",

    # --- Fake delivery / package scams ---
    "Your package could not be delivered. Click here to re-confirm your address and payment.",
    "DHL Notice: Your parcel is on hold. Pay a $2.99 customs fee to release your delivery.",
    "FedEx: We attempted to deliver your package. Click here to schedule redelivery now.",
    "UPS: Your package requires additional payment. Enter your credit card details below.",
    "Royal Mail: Your parcel is awaiting customs clearance. Pay fee to avoid return.",
    "USPS: Your package has been stopped. Provide your address and billing info to proceed.",
    "Amazon Delivery: Your order requires verification. Click here to confirm your details.",
    "Your delivery has been put on hold due to incomplete address. Update your info now.",

    # --- Fake IT / tech support alerts ---
    "Your computer has been infected with a virus! Call Microsoft support now at 1-800-XXX-XXXX.",
    "ALERT: Your Windows license has expired. Click here to renew your subscription now.",
    "Your Google account was accessed from an unfamiliar location. Secure it immediately.",
    "IMPORTANT: Your Outlook mailbox has reached its limit. Upgrade now to restore access.",
    "IT Security: We detected malware on your device. Download our tool immediately to remove.",
    "WARNING: Suspicious activity on your PayPal account. Verify your identity to unblock.",
    "Your iCloud account will be deleted. Verify your Apple ID to prevent data loss.",
    "Gmail Security: Someone tried to access your account. Click here to secure it now.",

    # --- Bank / financial fraud ---
    "You have a pending wire transfer. Verify your account details to receive your money.",
    "Your bank has flagged unusual transactions. Confirm your identity by clicking the link.",
    "URGENT: Large withdrawal detected on your account. Call us now to cancel and verify.",
    "We noticed an unauthorized transaction of $499. Confirm it was you or click to dispute.",
    "Your debit card has been blocked. Enter your PIN and CVV to unblock your card now.",
    "Dear Account Holder, your direct deposit has been returned. Verify your bank details.",
    "Suspicious transaction blocked. Your account is on hold. Verify your credentials now.",
    "Tax Refund: You are eligible for a $750 tax refund. Provide your bank account details.",

    # --- Social engineering / urgency ---
    "Your account will expire tonight if you don't take action. Click here to stay active.",
    "WARNING: This is your final warning before account termination. Act NOW!",
    "Your subscription has been compromised. Enter your password to continue using service.",
    "We noticed you haven't logged in recently. Verify your account or it will be deleted.",
    "FINAL REMINDER: Update your payment information in the next 2 hours or lose access.",
    "Act immediately! Your account shows signs of unauthorized access. Confirm your password.",
    "Alert: Your password was reset without your permission. Click here to cancel the change.",
    "IMPORTANT NOTICE: Your account login has been blocked due to multiple failed attempts.",

    # --- Malware / attachment lures ---
    "Please review the attached invoice for your recent purchase. Download and open the file.",
    "Your tax documents are ready. Download the attached PDF to view your tax return.",
    "Please review and sign the attached contract by clicking the link below.",
    "HR Department: Your payslip is attached. Please download and review immediately.",
    "URGENT: Legal documents require your signature. Open the attached file now.",
    "Invoice #INV-2024-00321 is overdue. Click below to download and pay immediately.",

    # --- Romance / advance fee scams ---
    "I am a soldier stationed abroad and need your help transferring $5 million to safety.",
    "My darling, I need you to wire money immediately. I am in trouble and need help now.",
    "I have business proposal for you that will make us both very rich. Please respond.",
]

SAFE_EMAILS = [
    # --- Work / professional ---
    "Hi John, just wanted to confirm our meeting tomorrow at 2pm. Please bring the documents.",
    "Hello team, here is the weekly project update. Let me know if you have any questions.",
    "Hi Sarah, great work on the presentation yesterday. The client was very impressed.",
    "Project update: We completed the first milestone. Next phase starts next Monday.",
    "Hi there, just following up on the proposal I sent last week. Any thoughts?",
    "Team lunch is scheduled for this Thursday at noon. RSVP by Wednesday.",
    "Your GitHub pull request has been reviewed and approved by the team.",
    "The quarterly report is attached. Please review before Friday's board meeting.",
    "Could you please send me the status update for the project by end of day?",
    "I wanted to introduce you to our new team member, Alex, who joins us on Monday.",
    "Following up on our call earlier, here is a summary of what we discussed.",
    "Happy to share that we closed the deal with the new client. Great team effort!",
    "The code review is complete. I left a few comments for your consideration.",
    "Just a quick note to say thank you for your help on the project last week.",
    "We've scheduled the sprint planning for next Tuesday at 10am. Please attend.",

    # --- Personal / social ---
    "Hey, are you free for lunch this Friday? Let me know what works for you.",
    "It was great seeing you at the conference! Let's stay in touch.",
    "Happy Birthday! Hope you have a wonderful day filled with joy and celebration.",
    "I just read your blog post. Fantastic insight on machine learning! Keep it up.",
    "Are you joining us for the game on Saturday? Let me know so I can get tickets.",
    "Checking in to see how you're doing. We should catch up sometime soon!",
    "Just wanted to say congratulations on your promotion. Well deserved!",
    "Hi, I wanted to share this interesting article about machine learning I came across.",

    # --- E-commerce / order confirmations ---
    "Your order has been shipped! Track your package using the link in this email.",
    "Your invoice for March is ready. Please find the attached PDF for your records.",
    "Your flight booking is confirmed. Check-in opens 24 hours before departure.",
    "Your subscription renewal date is March 15. No action needed if you wish to continue.",
    "Your Amazon order #112-4398762 has been delivered to your front door.",
    "Thanks for your purchase! Your receipt is attached for your records.",
    "Your Uber Eats order is on its way. Estimated delivery time: 25-35 minutes.",
    "Your hotel reservation at Marriott Downtown is confirmed for March 18-21.",

    # --- Newsletters / notifications ---
    "Thanks for subscribing to our newsletter. Here is your monthly digest of top articles.",
    "New comment on your blog post: someone found your article very helpful.",
    "Congratulations on completing the course! Your certificate is ready to download.",
    "Your weekly summary from LinkedIn: 15 new connections and 3 messages.",
    "GitHub: Your repository received 5 new stars this week.",
    "Stack Overflow: You've earned the 'Enthusiast' badge for visiting 30 days in a row.",
    "Medium: Your story was featured in the Daily Digest and received 200 views.",
    "We've added new features to the platform based on community feedback this month.",

    # --- Appointment / calendar ---
    "Reminder: Your dentist appointment is scheduled for Monday at 10am.",
    "Your car service appointment is confirmed for Saturday at 9:00 AM.",
    "Your video call with Dr. Smith is tomorrow at 3:30 PM. Here is the meeting link.",
    "Just a reminder that your annual health checkup is due next month.",

    # --- HR / company ---
    "Welcome to the platform! We are excited to have you on board. Start exploring today.",
    "Dear applicant, we reviewed your application and would like to schedule an interview.",
    "Your paycheck for February has been processed and will arrive within 2 business days.",
    "This is a reminder that the company holiday party is on December 20 at 6 PM.",
    "Your benefits enrollment period opens next Monday. Please review your options.",
    "HR Update: The new remote work policy document is now available on the intranet.",
    "Congratulations! You have been approved for 5 days of paid vacation starting March 10.",

    # --- Simple utility / info ---
    "Your weekly GitHub activity: 12 commits, 3 pull requests, 2 issues closed.",
    "Here is the link to the recording of today's webinar as requested.",
    "Your two-factor authentication code is 847293. Do not share this with anyone.",
    "Attached is the document you requested yesterday. Let me know if you need anything else.",
    "The system maintenance window is scheduled for Sunday 2-4 AM. Expect brief downtime.",
    "Your password was successfully changed. If you did not make this change, contact support.",
    "Your account settings have been updated as requested. No further action is needed.",
    "New version 3.2.1 of the app is now available. Update to get the latest improvements.",
]


def build_email_dataset():
    texts, labels = [], []
    for email in PHISHING_EMAILS:
        texts.append(email)
        labels.append(1)   # 1 = phishing
    for email in SAFE_EMAILS:
        texts.append(email)
        labels.append(0)   # 0 = safe
    return texts, labels


# ============================================================
# 3. TRAIN URL MODEL (Random Forest)
# ============================================================

def train_url_model():
    print("\n== Training URL Phishing Detection Model ==")
    X, y = build_url_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        class_weight='balanced',
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    joblib.dump(model, 'url_model.pkl')
    print("Saved: url_model.pkl")
    return model


# ============================================================
# 4. TRAIN EMAIL MODEL (TF-IDF + Logistic Regression)
# ============================================================

def train_email_model():
    print("\n== Training Email Phishing Detection Model ==")
    texts, labels = build_email_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # Pipeline: TF-IDF vectorizer → Logistic Regression classifier
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 3),   # unigrams + bigrams + trigrams
            max_features=10000,
            sublinear_tf=True,
            min_df=1,
        )),
        ('clf', LogisticRegression(
            C=5.0,                # higher C = less regularization = more sensitive
            max_iter=1000,
            class_weight='balanced',
            random_state=42
        )),
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print(classification_report(y_pred, y_test, target_names=['Safe', 'Phishing']))

    joblib.dump(pipeline, 'email_model.pkl')
    print("Saved: email_model.pkl")
    return pipeline


# ============================================================
# 5. MAIN
# ============================================================

if __name__ == '__main__':
    train_url_model()
    train_email_model()
    print("\nAll models trained and saved successfully!")
    print("Now run:  python app.py")
