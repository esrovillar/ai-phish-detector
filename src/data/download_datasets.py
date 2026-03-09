"""
Dataset Downloader — Download public phishing/ham email datasets.

Downloads SpamAssassin public corpus and creates a structured
data/emails/ directory with phishing/ and legitimate/ subdirectories.
Falls back to synthetic data generation if downloads fail.
"""

import email
import os
import io
import tarfile
import shutil
import random
import string
from datetime import datetime, timedelta

import click
import requests


DATA_DIR = os.path.join("data", "emails")
PHISHING_DIR = os.path.join(DATA_DIR, "phishing")
LEGITIMATE_DIR = os.path.join(DATA_DIR, "legitimate")

# SpamAssassin public corpus URLs
SPAMASSASSIN_URLS = {
    "ham": [
        "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    ],
    "spam": [
        "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
    ],
}


def _ensure_dirs():
    """Create data directories if they don't exist."""
    os.makedirs(PHISHING_DIR, exist_ok=True)
    os.makedirs(LEGITIMATE_DIR, exist_ok=True)


def _download_and_extract(url: str, target_dir: str, label: str) -> int:
    """
    Download a tar.bz2 archive, extract email files to target_dir.
    Returns count of extracted files.
    """
    click.echo(f"  Downloading {url}...")
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
    except Exception as e:
        click.echo(f"  ✗ Download failed: {e}")
        return 0

    click.echo(f"  Extracting to {target_dir}...")
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:bz2") as tar:
            for member in tar.getmembers():
                if member.isfile() and not member.name.endswith("cmds"):
                    f = tar.extractfile(member)
                    if f:
                        content = f.read()
                        # Save as .eml file
                        filename = f"{label}_{count:04d}.eml"
                        filepath = os.path.join(target_dir, filename)
                        with open(filepath, "wb") as out:
                            out.write(content)
                        count += 1
    except Exception as e:
        click.echo(f"  ✗ Extraction failed: {e}")

    return count


def _generate_synthetic_phishing(count: int = 50) -> int:
    """Generate synthetic phishing emails for fallback training data."""
    subjects = [
        "URGENT: Your account has been compromised!",
        "Action Required: Verify your identity immediately",
        "Your PayPal account has been limited",
        "Suspicious login attempt detected on your account",
        "Your package delivery failed - Click here to reschedule",
        "You've won a $1000 Amazon Gift Card!",
        "ALERT: Unauthorized transaction on your account",
        "Your Microsoft 365 password expires today",
        "Final Notice: Account will be suspended",
        "Security Alert: Update your banking information",
        "IRS Tax Refund Notification",
        "Netflix: Payment declined - Update now",
        "Apple ID Locked - Verify your identity",
        "LinkedIn: Someone viewed your profile",
        "Your Wells Fargo account requires attention",
    ]

    bodies = [
        """<html><body>
<p>Dear Valued Customer,</p>
<p>We have detected <b>unauthorized activity</b> on your account.
Your account has been temporarily <b>SUSPENDED</b>.</p>
<p>To restore access, please <a href="http://paypa1-secure.xyz/verify">click here to verify your identity</a> immediately.</p>
<p>If you do not verify within 24 hours, your account will be permanently closed.</p>
<p>Thank you,<br>PayPal Security Team</p>
</body></html>""",
        """<html><body>
<p>URGENT SECURITY ALERT</p>
<p>We noticed a sign-in attempt from an unrecognized device:</p>
<ul><li>Location: Moscow, Russia</li><li>Device: Unknown</li></ul>
<p>If this wasn't you, <a href="http://micr0soft-login.top/secure">secure your account now</a>.</p>
<p>Microsoft Security Team</p>
</body></html>""",
        """<html><body>
<p>Congratulations! You've been selected to receive a $500 gift card!</p>
<p>Click <a href="http://192.168.1.100/claim">HERE</a> to claim your reward before it expires!</p>
<p>Limited time offer - act NOW!</p>
</body></html>""",
        """<html><body>
<p>Dear Customer,</p>
<p>Your Netflix subscription payment was declined.</p>
<p>Please update your payment method at <a href="http://bit.ly/3xFake">http://netflix.com/billing</a> to avoid service interruption.</p>
<p>Netflix Support</p>
</body></html>""",
        """<html><body>
<p>Your Wells Fargo Online Banking access has been restricted due to suspicious activity.</p>
<p>To restore full access, verify your information: <a href="http://wells-farg0.cf/verify">Verify Now</a></p>
<p>This is time-sensitive. Failure to act within 48 hours will result in permanent account closure.</p>
</body></html>""",
    ]

    generated = 0
    for i in range(count):
        msg = email.message.EmailMessage()
        msg["From"] = f"security@{''.join(random.choices(string.ascii_lowercase, k=6))}.{random.choice(['xyz', 'top', 'click', 'ml'])}"
        msg["To"] = "victim@example.com"
        msg["Subject"] = random.choice(subjects)
        msg["Date"] = (datetime.now() - timedelta(days=random.randint(1, 365))).strftime("%a, %d %b %Y %H:%M:%S +0000")
        msg["X-Mailer"] = random.choice(["PHPMailer 6.0", "Python/3.9", "SwiftMailer", ""])
        msg["Reply-To"] = f"reply@{''.join(random.choices(string.ascii_lowercase, k=8))}.com"
        msg["Return-Path"] = f"bounce@{''.join(random.choices(string.ascii_lowercase, k=5))}.net"
        msg["X-Priority"] = random.choice(["1", "2", "3"])

        body = random.choice(bodies)
        msg.set_content(body, subtype="html")

        filepath = os.path.join(PHISHING_DIR, f"synth_phish_{i:04d}.eml")
        with open(filepath, "w") as f:
            f.write(msg.as_string())
        generated += 1

    return generated


def _generate_synthetic_legitimate(count: int = 50) -> int:
    """Generate synthetic legitimate emails for fallback training data."""
    subjects = [
        "Meeting Tomorrow at 10am",
        "Re: Project Update",
        "Q3 Report Attached",
        "Lunch plans for Friday?",
        "Your order has shipped",
        "Newsletter: Weekly Digest",
        "Team standup notes",
        "Re: Re: Vacation request",
        "Invoice #4521 from ACME Corp",
        "Welcome to our platform",
        "Your appointment confirmation",
        "Monthly statement available",
        "Happy Birthday!",
        "Conference registration confirmed",
        "Document review requested",
    ]

    bodies = [
        "Hi team,\n\nJust a reminder about our meeting tomorrow at 10am in the main conference room.\n\nPlease bring your project updates.\n\nBest,\nJohn",
        "Hey,\n\nWanted to check if you're free for lunch on Friday? There's a new place downtown I've been wanting to try.\n\nLet me know!\nSarah",
        "Hello,\n\nPlease find attached the Q3 financial report for your review. Let me know if you have any questions.\n\nRegards,\nAccounting Team",
        "Hi,\n\nYour order #12345 has been shipped via FedEx. Tracking number: 7894561230.\n\nEstimated delivery: 3-5 business days.\n\nThanks for your purchase!",
        "Good morning,\n\nHere are the notes from today's standup:\n- Backend API migration is 80% complete\n- Frontend redesign starts next sprint\n- QA testing for release 2.1 in progress\n\nCheers,\nMike",
    ]

    generated = 0
    for i in range(count):
        msg = email.message.EmailMessage()
        name = random.choice(["John Smith", "Sarah Johnson", "Mike Chen", "Lisa Park", "David Brown"])
        domain = random.choice(["company.com", "example.org", "work.com", "corp.net"])
        from_addr = f"{name.split()[0].lower()}@{domain}"
        msg["From"] = f"{name} <{from_addr}>"
        msg["To"] = "user@company.com"
        msg["Subject"] = random.choice(subjects)
        msg["Date"] = (datetime.now() - timedelta(days=random.randint(1, 365))).strftime("%a, %d %b %Y %H:%M:%S +0000")
        msg["Message-ID"] = f"<{''.join(random.choices(string.hexdigits, k=16))}@{domain}>"
        msg["Return-Path"] = f"<{from_addr}>"
        msg["Authentication-Results"] = f"{domain}; spf=pass; dkim=pass; dmarc=pass"

        body = random.choice(bodies)
        msg.set_content(body)

        filepath = os.path.join(LEGITIMATE_DIR, f"synth_legit_{i:04d}.eml")
        with open(filepath, "w") as f:
            f.write(msg.as_string())
        generated += 1

    return generated


@click.command()
@click.option("--output", "-o", default=DATA_DIR, help="Output directory for emails")
@click.option("--synthetic-only", is_flag=True, help="Skip downloads, generate synthetic data only")
@click.option("--count", "-n", default=50, help="Number of synthetic emails per class")
def download(output, synthetic_only, count):
    """Download or generate training email datasets."""
    global DATA_DIR, PHISHING_DIR, LEGITIMATE_DIR
    DATA_DIR = output
    PHISHING_DIR = os.path.join(DATA_DIR, "phishing")
    LEGITIMATE_DIR = os.path.join(DATA_DIR, "legitimate")

    _ensure_dirs()

    if not synthetic_only:
        click.echo("📥 Downloading SpamAssassin corpus...")

        # Download ham (legitimate)
        ham_count = 0
        for url in SPAMASSASSIN_URLS["ham"]:
            ham_count += _download_and_extract(url, LEGITIMATE_DIR, "ham")

        # Download spam (phishing)
        spam_count = 0
        for url in SPAMASSASSIN_URLS["spam"]:
            spam_count += _download_and_extract(url, PHISHING_DIR, "spam")

        click.echo(f"  ✓ Downloaded {ham_count} legitimate, {spam_count} phishing emails")

        if ham_count > 0 and spam_count > 0:
            click.echo("✅ Dataset ready!")
            return

        click.echo("⚠️  Downloads incomplete, falling back to synthetic data...")

    # Generate synthetic data
    click.echo(f"🔧 Generating {count} synthetic emails per class...")
    phish_count = _generate_synthetic_phishing(count)
    legit_count = _generate_synthetic_legitimate(count)
    click.echo(f"  ✓ Generated {phish_count} phishing, {legit_count} legitimate emails")
    click.echo("✅ Synthetic dataset ready!")


if __name__ == "__main__":
    download()
