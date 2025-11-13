"""
Streamlit Password Strength Checker
Converted from a CLI script to a Streamlit UI.
Save as `streamlit_password_checker.py` and run with:
    streamlit run streamlit_password_checker.py

Requires: streamlit, requests, password_strength, matplotlib, colorama
Install with: pip install streamlit requests password-strength matplotlib colorama
"""
import re
import math
import hashlib
import requests
import matplotlib.pyplot as plt
from collections import Counter
from password_strength import PasswordPolicy
from colorama import Fore, Style, init
import streamlit as st

# Initialize colorama for terminal-like messages (still useful if app logs to console)
init(autoreset=True)

# URL for common passwords list (you can replace it with any other list URL)
COMMON_PASSWORDS_URL = 'https://raw.githubusercontent.com/dwyl/english-words/master/words.txt'

# Password strength policy
policy = PasswordPolicy.from_names(
    length=12,  # Minimum length
    uppercase=1,  # At least 1 uppercase
    numbers=1,  # At least 1 number
    special=1,  # At least 1 special character
    nonletters=1  # At least 1 non-letter character
)

# Cache the common password download so it does not run on every interaction
@st.cache_data(ttl=60*60*24)  # cache 1 day
def download_common_passwords():
    try:
        response = requests.get(COMMON_PASSWORDS_URL, timeout=10)
        response.raise_for_status()
        passwords = set(response.text.splitlines())
        return passwords
    except requests.exceptions.RequestException as e:
        # We can't use Fore coloring reliably in Streamlit output, but we keep the message for logs
        print(f"Error contacting the passwords list: {e}")
        return set()

common_passwords = download_common_passwords()

# Function to calculate entropy
def calculate_entropy(password):
    if not password:
        return 0.0
    char_set_size = len(set(password))  # Unique characters
    password_length = len(password)
    # Avoid log2(0)
    if char_set_size == 0:
        return 0.0
    entropy = password_length * math.log2(char_set_size)
    return round(entropy, 2)

# Check if password exposed using HIBP k-anonymity API
def check_pwned_password(password):
    if not password:
        return False, 0
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars = sha1_password[:5]
    rest_of_hash = sha1_password[5:]
    url = f'https://api.pwnedpasswords.com/range/{first5_chars}'
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error contacting API: {e}")
        return False, 0
    if response.status_code == 200:
        hashes = (line.split(":") for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == rest_of_hash:
                try:
                    return True, int(count)
                except ValueError:
                    return True, 0
    return False, 0

# Check for dictionary words / common passwords
def contains_common_words(password):
    if not password:
        return False
    return password.lower() in common_passwords

# Provide feedback (stream-friendly strings, without console colors)
def give_feedback(password):
    feedback = []
    if len(password) < 12:
        feedback.append("Password too short — consider making it at least 12 characters.")
    if not re.search(r'[a-z]', password):
        feedback.append("Add at least one lowercase letter.")
    if not re.search(r'[A-Z]', password):
        feedback.append("Add at least one uppercase letter.")
    if not re.search(r'[0-9]', password):
        feedback.append("Add at least one number.")
    if not re.search(r'[@#$%^&+=!]', password):
        feedback.append("Add at least one special character (e.g. @ # $ % ^ & + = !).")
    if not feedback:
        feedback.append("Password passes basic checks (length & character classes).")
    return feedback

# Password rating system
def password_rating(entropy, breach_score, length_score, repetition_score):
    total_score = entropy / 4.0 + breach_score + length_score + repetition_score
    # entropy scaled down so that typical values fit into the rating system
    if total_score >= 30:
        return "Good", round(total_score, 2)
    elif total_score >= 20:
        return "Fair", round(total_score, 2)
    else:
        return "Poor", round(total_score, 2)

# Advanced password strength checker (returns structured data for UI)
def check_advanced_password_strength(password):
    result = {
        'contains_common': False,
        'policy_issues': [],
        'repetition_issue': False,
        'pwned': False,
        'pwned_count': 0,
        'entropy': 0.0,
        'length': len(password),
        'rating': 'Unknown',
        'total_score': 0.0
    }

    # Common words
    if contains_common_words(password):
        result['contains_common'] = True

    # Policy test
    strength = policy.test(password)
    if strength:
        result['policy_issues'] = [str(x) for x in strength]

    # Repetition check
    if any(v > 2 for v in Counter(password).values()):
        result['repetition_issue'] = True

    # Pwned check
    pwned, breach_count = check_pwned_password(password)
    result['pwned'] = pwned
    result['pwned_count'] = breach_count

    # Entropy & scores
    entropy = calculate_entropy(password)
    result['entropy'] = entropy
    length_score = 5 if len(password) >= 12 else 0
    repetition_score = 0 if all(v <= 2 for v in Counter(password).values()) else 5
    breach_score = 0
    if pwned:
        if breach_count <= 5:
            breach_score = 5
        elif breach_count <= 20:
            breach_score = 10
        else:
            breach_score = 15

    rating, total_score = password_rating(entropy, breach_score, length_score, repetition_score)
    result['rating'] = rating
    result['total_score'] = total_score

    return result

# Visualization helper
def plot_report(entropy, breach_count, password_length, rating):
    categories = ['Entropy', 'Breach Count', 'Password Length']
    values = [entropy, breach_count, password_length]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(categories, values)
    ax.set_title(f"Password Strength Report ({rating})")
    ax.set_ylabel('Value')
    return fig

# Streamlit UI
st.set_page_config(page_title='Password Strength Checker', layout='centered')
st.title('🔒 Password Strength Checker')
st.write('Enter a password below and click **Analyze**. This tool checks basic composition, entropy, common-word lists and whether the password has appeared in public breaches (k-anonymized check).')

with st.form(key='password_form'):
    pw = st.text_input('Password', type='password')
    show_pw = st.checkbox('Show password')
    if show_pw:
        st.write('You entered:', pw)
    analyze = st.form_submit_button('Analyze')

if analyze:
    if not pw:
        st.warning('Please enter a password to analyze.')
    else:
        st.info('Running checks...')
        res = check_advanced_password_strength(pw)

        # Feedback
        st.subheader('Feedback')
        feedback_list = give_feedback(pw)
        for f in feedback_list:
            st.write('- ', f)

        if res['contains_common']:
            st.error('Password found in the common-words list. Avoid dictionary words.')

        if res['policy_issues']:
            st.error('Password policy issues:')
            for issue in res['policy_issues']:
                st.write('- ', issue)

        if res['repetition_issue']:
            st.warning("Password contains repeated characters (e.g., 'aaa' or '111').")

        if res['pwned']:
            st.error(f"This password has been seen in data breaches {res['pwned_count']} times.")
        else:
            st.success('No public breach record found for this password (via k-anonymized check).')

        # Rating and numeric outputs
        st.subheader('Score & Metrics')
        st.write('Entropy:', res['entropy'])
        st.write('Password length:', res['length'])
        st.write('Rating:', res['rating'])
        st.write('Total score (scaled):', res['total_score'])

        # Strength meter (progress bar)
        # Map rating to progress value
        progress_val = min(1.0, max(0.0, res['total_score'] / 40.0))
        st.progress(progress_val)

        # Plot
        fig = plot_report(res['entropy'], res['pwned_count'], res['length'], res['rating'])
        st.pyplot(fig)

        st.caption('Note: No password is sent in full to us here other than your browser communicating with HaveIBeenPwned API for the k-anonymity check. Use this tool locally for sensitive passwords.')

st.markdown('---')
st.write('Tips: Use a passphrase of multiple random words or a password manager to generate and store unique passwords.')
