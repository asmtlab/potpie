import typer
import string
import re
import json
import hashlib
import requests
import time
import importlib.metadata
import plotly.graph_objects as go
import plotly.express as px
from collections import Counter, defaultdict
from jinja2 import Environment, FileSystemLoader
import os
from potpie.logger import init_logger, logger, console
from potpie import __version__

app = typer.Typer(
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)

# Rate limit HIBP
HIBP_API_DELAY = 1.6  # seconds

def print_banner():
    console.print("""[blue]
    potpie
    [/]""")


def print_version():
    version = importlib.metadata.version("potpie")
    console.print(f"[bold red]potpie[/] v{version}")


def help():
    print_banner()
    print_version()


def get_complexity_flags(pw):
    return {
        'uppercase': any(c.isupper() for c in pw),
        'lowercase': any(c.islower() for c in pw),
        'number': any(c.isdigit() for c in pw),
        'special': any(c in string.punctuation for c in pw),
    }


def get_mask(pw):
    mask = ""
    for c in pw:
        if c.isupper():
            mask += "?u"
        elif c.islower():
            mask += "?l"
        elif c.isdigit():
            mask += "?d"
        elif c in string.punctuation:
            mask += "?s"
        else:
            mask += "?x"  # unknown/other
    return mask


def plot_cracked_pie_chart(total_hashes, total_cracked):
    uncracked = total_hashes - total_cracked
    colors = ['#C41230', '#5E9732']
    fig = go.Figure(data=[
        go.Pie(labels=['Cracked', 'Uncracked'], values=[total_cracked, uncracked], hole=0.3, marker_colors=colors)
    ])
    fig.update_layout(template='plotly_dark')
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def plot_password_length_chart(passwords):
    lengths = [len(p) for p in passwords]
    sorted_lengths = sorted(lengths)
    max_length = max(sorted_lengths) if sorted_lengths else 0
    x_vals = [str(i) for i in range(0, max_length + 1)]
    avg_length = sum(lengths) / len(lengths) if lengths else 0

    fig = go.Figure()
    fig.add_trace(go.Histogram(x=sorted_lengths, nbinsx=12, name='Length Distribution', marker_color='rgb(0, 120, 174)'))
    fig.add_shape(
        type='line',
        x0=avg_length, x1=avg_length, y0=0, y1=1, xref='x', yref='paper',
        line=dict(color='rgb(196, 18, 48)', dash='dash'),
        name='Average Length',
        showlegend=True
    )
    fig.update_layout(xaxis=dict(type="category", categoryorder="array", categoryarray=x_vals, title='Password Length'), yaxis_title='# Passwords', template='plotly_dark')
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def plot_complexity_chart(complexity_scores):
    sorted_scores = sorted(complexity_scores)
    x_vals = [str(i) for i in range(0, 5)]
    fig = go.Figure()
    fig.add_trace(go.Histogram(x=sorted_scores, nbinsx=10, name='Degree of Complexity', marker_color='rgb(0, 120, 174)'))
    avg_score = sum(complexity_scores) / len(complexity_scores) if complexity_scores else 0
    fig.add_shape(
        type='line',
        x0=avg_score, x1=avg_score, y0=0, y1=1, xref='x', yref='paper',
        line=dict(color='rgb(196, 18, 48)', dash='dash'),
        name='Average Complexity',
        showlegend=True
    )
    fig.update_layout(xaxis=dict(type="category", categoryorder="array", categoryarray=x_vals, title='Password Complexity'), yaxis_title='# Passwords', template='plotly_dark')
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def plot_top_masks_chart(mask_counter):
    filtered = {pw: count for pw, count in mask_counter.items() if count > 1}
    sorted_mask = sorted(filtered.items(), key=lambda x: x[1], reverse=True)[:10]
    labels = [item[0] for item in sorted_mask]
    values = [item[1] for item in sorted_mask]

    fig = go.Figure(go.Bar(x=labels, y=values, marker_color='rgb(0, 120, 174)'))
    fig.update_layout(xaxis_title='Mask', yaxis_title='# Passwords', template='plotly_dark')
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def plot_top_passwords_chart(pw_counter):
    filtered = {pw: count for pw, count in pw_counter.items() if count > 1}
    sorted_pw = sorted(filtered.items(), key=lambda x: x[1], reverse=True)[:10]
    labels = [pw for pw, _ in sorted_pw]
    values = [count for _, count in sorted_pw]

    fig = go.Figure(go.Bar(x=labels, y=values, marker_color='rgb(0, 120, 174)'))
    fig.update_layout(xaxis_title='Password', yaxis_title='# Accounts', template='plotly_dark')
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def query_hibp_sha1(password):
    """
    Queries the HIBP API for a given password using the k-anonymity model.
    Returns the number of times a password appeared in breaches.
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        print(f"Error querying HaveIBeenPwned: {response.status_code}")
        return 0

    for line in response.text.splitlines():
        returned_suffix, count = line.strip().split(":")
        if returned_suffix == suffix:
            return int(count)
    return 0


def generate_hibp_metrics(passwords):
    """
    Generates breach exposure metrics using the HIBP API.
    """
    password_counts = Counter(passwords)
    unique_passwords = list(password_counts.keys())

    hibp_results = {}
    for pwd in unique_passwords:
        try:
            count = query_hibp_sha1(pwd)
            hibp_results[pwd] = count
            time.sleep(HIBP_API_DELAY)
        except Exception as e:
            print(f"Error processing password '{pwd}': {e}")
            hibp_results[pwd] = 0

    total_cracked = sum(password_counts.values())
    cracked_in_hibp = sum(1 for pwd in unique_passwords if hibp_results.get(pwd, 0) > 0)
    avg_breach_count = round(sum(hibp_results.get(pwd, 0) for pwd in unique_passwords) / len(unique_passwords))

    top_passwords = sorted(hibp_results.items(), key=lambda x: x[1], reverse=True)[:10]

    breach_distribution = defaultdict(int)
    for count in hibp_results.values():
        if count == 0:
            continue
        elif count < 10:
            breach_distribution["1"] += 1
        elif count < 1_000:
            breach_distribution["2"] += 1
        elif count < 10_000:
            breach_distribution["3"] += 1
        elif count < 1_000_000:
            breach_distribution["4"] += 1
        else:
            breach_distribution["5"] += 1

    hibp_metrics = {
        "total_cracked_passwords": total_cracked,
        "unique_passwords": len(unique_passwords),
        "cracked_passwords_found_in_HIBP": cracked_in_hibp,
        "percentage_found_in_HIBP": (cracked_in_hibp / len(unique_passwords)) * 100,
        "average_breach_count": avg_breach_count,
        "top_breached_passwords": top_passwords,
        "breach_count_distribution": dict(breach_distribution),
    }

    return hibp_metrics


def create_hibp_dial(breach_percentage):
    percentage = max(0, min(breach_percentage, 100))

    if percentage <= 25:
        fill_color = "green"
    elif percentage <= 50:
        fill_color = "orange"
    else:
        fill_color = "red"

    values = [percentage, 100 - percentage]
    colors = [fill_color, "lightgray"]

    fig = go.Figure(data=[go.Pie(values=values, marker_colors=colors, hole=0.7, sort=False, direction='clockwise', textinfo='none', hoverinfo='skip')])
    fig.add_annotation(text=f"{percentage:.0f}%", font_size=40, showarrow=False)
    fig.update_layout(showlegend=False, margin=dict(t=20, b=20, l=20, r=20), height=400, width=400, template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def plot_breach_distribution_chart(average_breach_count, breach_distribution):
    sorted_data = [breach_distribution.get(key, 0) for key in ["1", "2", "3", "4", "5"]]
    x_vals = ["<10", "10-999", "1k-10k", "10k-1M", "1M+"]
    fig = px.bar(x=x_vals, y=sorted_data, labels={'x': 'Breach Exposure', 'y': '# Passwords'}, template='plotly_dark')
    fig.update_traces(marker_color='rgb(0, 120, 174)')
    return fig.to_html(full_html=False, include_plotlyjs='cdn')


def generate_html_report(metrics, charts, hibp_metrics, hibp_charts, output_path="./report/potpie_report.html"):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template("./potpie_template.html")

    rendered_html = template.render(metrics=metrics, charts=charts, hibp=hibp_metrics, hibp_charts=hibp_charts)

    with open(output_path, "w") as f:
        f.write(rendered_html)

    print(f"HTML report saved to {output_path}")


@app.command(no_args_is_help=True, help=help())
def main(
    min_length: int = typer.Option(..., '--length', '-l', help='Minimum password length (per policy)'),
    require_complexity: bool = typer.Option(False, '--complex', help='Password complexity is enforced (per policy)'),
    ntds: typer.FileText = typer.Option(..., '--ntds', '-n', help='Path to the NTDS.dit file'),
    potfile: typer.FileText = typer.Option(..., '--potfile', '-p', help='Path to the hashcat potfile'),
    admins: typer.FileText = typer.Option(None, '--admins', '-a', help='Path to file containing list of administrators'),
    kerb: typer.FileText = typer.Option(None, '--kerb', '-k', help='Path to file containing list of kerberoastable accounts'),
    breach: bool = typer.Option(False, '--breach', help='Enable HaveIBeenPwned breach analysis (~1.6s per cracked password)'),
    breach_data: typer.FileText = typer.Option(None, '--breach-data', help='Path to file containing HaveIBeenPwned breach data'),
    debug: bool = typer.Option(False, '--debug', help='Enable [green]DEBUG[/] output')):

    init_logger(debug)

    cracked_passwords = {}
    for line in potfile:
        h, pw = line.strip().split(":", 1)
        cracked_passwords[h.lower()] = pw

    accounts = []
    for line in ntds:
        parts = line.strip().lower().split(":")
        if len(parts) >= 4:
            raw_username = parts[0]
            domain = raw_username.split("\\")[0] if "\\" in raw_username else ""
            username = raw_username.split("\\")[-1]
            if username[-1] == '$':
                continue  # Skip machine accounts
            else:
                nt_hash = parts[3].lower()
                plaintext = cracked_passwords.get(nt_hash)
                accounts.append({
                    "domain": domain,
                    "username": username,
                    "nt_hash": nt_hash,
                    "plaintext": plaintext # will be None if not cracked
                })
    
    # Total cracked password metrics
    total_hashes = len(accounts)
    total_cracked = sum(1 for acc in accounts if acc['plaintext'] is not None)

    # Unique cracked password metrics
    unique_hashes = {acc['nt_hash'] for acc in accounts}
    unique_cracked = {acc['nt_hash'] for acc in accounts if acc['plaintext'] is not None}
    total_unique_hashes = len(unique_hashes)
    total_unique_cracked = len(unique_cracked)

    # Administrator accounts
    admin_accounts = []
    if admins:
        for line in admins:
            account = line.strip().lower()
            admin_accounts.append(account)
        admin_hashes = [acc for acc in accounts if acc['username'] in admin_accounts]
        total_admin = len(admin_hashes)
        cracked_admin = [acc for acc in admin_hashes if acc['plaintext'] is not None]
        total_cracked_admin = len(cracked_admin)
    else:
        total_admin = "N/A"
        total_cracked_admin = "N/A"

    # Kerberoastable accounts
    kerb_accounts = []
    if kerb:
        for line in kerb:
            account = line.strip().lower()
            kerb_accounts.append(account)
        kerberoastable_hashes = []
        for acc in accounts:
            if acc['domain']:
                account_name = f"{acc['domain']}\\{acc['username']}"
            else:
                account_name = acc['username']
            if account_name in kerb_accounts:
                kerberoastable_hashes.append(acc)
        total_kerberoastable = len(kerberoastable_hashes)
        cracked_kerberoastable = [acc for acc in kerberoastable_hashes if acc['plaintext'] is not None]
        total_cracked_kerberoastable = len(cracked_kerberoastable)
    else:
        total_kerberoastable = "N/A"
        total_cracked_kerberoastable = "N/A"

    # Password length analysis
    passwords = [acc['plaintext'] for acc in accounts if acc['plaintext'] is not None]
    avg_length = sum(len(pw) for pw in passwords) / len(passwords) if passwords else 0
    shortest_password = min(passwords, key=len)
    shortest_password_length = len(shortest_password) if shortest_password else 0
    longest_password = max(passwords, key=len)
    longest_password_length = len(longest_password) if longest_password else 0

    # Password complexity analysis
    complexity_scores = [sum(get_complexity_flags(pw).values()) for pw in passwords]
    avg_complexity = sum(complexity_scores) / len(complexity_scores)

    complexity_score_counter = Counter(complexity_scores)

    char_class_counter = Counter()
    for pw in passwords:
        flags = get_complexity_flags(pw)
        for k, v in flags.items():
            if v:
                char_class_counter[k] += 1

    # Password mask analysis
    mask_counter = Counter(get_mask(pw) for pw in passwords)
    mask_list = [(mask, count) for mask, count in mask_counter.items() if count > 1]
    top_10_masks = sorted(mask_list, key=lambda x: -x[1])[:10]
    
    # Guessable password analysis
    common_patterns = [
        r"(spring|summer|fall|autumn|winter)\d{2,4}[!@#$%^&*]*",    # Season pattern
        r"(password|p@ssword|p@ssw0rd|passw0rd)\d*[!@#$%^&]*",  # password variants
        r"welcome\d*",  # welcome variants
        r"admin\d*",    # admin variants
        r"(letmein|changeme|qwerty|123456|12345678|1234567890)",    # known weak phrases
    ]

    combined_re = re.compile("|".join(common_patterns), re.IGNORECASE)
    password_counter = Counter(passwords)
    guessable_passwords = [(pw, count) for pw, count in password_counter.items() if combined_re.search(pw)]
    guessable_count = len(guessable_passwords)

    # Username = password matches
    user_pw_match = [(acc['domain'], acc['username']) for acc in accounts if acc["plaintext"] and acc["plaintext"].lower() == acc["username"].lower()]

    # Top 10 common passwords
    pw_counter = Counter(pw for pw in passwords)
    reused_pw_list = [(pw, count) for pw, count in pw_counter.items() if count > 1]
    top_10_reused = sorted(reused_pw_list, key=lambda x: -x[1])[:10]

    # Password policy violations
    length_violations = []
    complexity_violations = []

    for acc in accounts:
        pw = acc["plaintext"]
        if not pw:
            continue
        too_short = len(pw) < min_length
        flags = get_complexity_flags(pw)
        classes_used = sum(flags.values())
        complexity_fail = require_complexity and classes_used < 3
        if too_short:
            length_violations.append((acc['domain'], acc['username']))
        if complexity_fail:
            complexity_violations.append((acc['domain'], acc['username']))

    # HIBP breach exposure metrics
    hibp_metrics = {}
    if breach_data:
        print(f"Loading HaveIBeenPwned breach data from {breach_data.name}...")
        try:
            hibp_metrics = json.load(breach_data)
        except Exception as e:
            print(f"Error loading HaveIBeenPwned data: {e}")
            hibp_metrics = {}
    elif breach:
        print("Generating HaveIBeenPwned breach exposure metrics (this may take a while)...")
        hibp_metrics = generate_hibp_metrics(passwords)
        os.makedirs(os.path.dirname("./report/hibp_data.json"), exist_ok=True)
        with open("./report/hibp_data.json", "w") as f:
            json.dump(hibp_metrics, f, indent=4)
    else:
        print("Skipping HaveIBeenPwned breach analysis.")

    hibp_charts = {}
    if hibp_metrics:
        breach_percentage = hibp_metrics.get("percentage_found_in_HIBP", 0)
        average_breach_count = hibp_metrics.get("average_breach_count", 0)
        breach_distribution = hibp_metrics.get("breach_count_distribution", {})
        hibp_charts['breach_dial'] = create_hibp_dial(breach_percentage)
        hibp_charts['breach_distribution_chart'] = plot_breach_distribution_chart(average_breach_count, breach_distribution)

    # Generate HTML report
    metrics = {
        "total_hashes": total_hashes,
        "total_cracked": total_cracked,
        "total_cracked_percent": f"{(total_cracked / total_hashes * 100):.2f}%" if total_hashes > 0 else "0%",
        "total_unique_hashes": total_unique_hashes,
        "total_unique_cracked": total_unique_cracked,
        "total_unique_cracked_percent": f"{(total_unique_cracked / total_unique_hashes * 100):.2f}%" if total_unique_hashes > 0 else "0%",
        "total_admin": total_admin,
        "total_cracked_admin": total_cracked_admin,
        "total_kerberoastable": total_kerberoastable,
        "total_cracked_kerberoastable": total_cracked_kerberoastable,
        "avg_length": avg_length,
        "shortest_password_length": shortest_password_length,
        "longest_password_length": longest_password_length,
        "avg_complexity": avg_complexity,
        "complexity_score_counter": complexity_score_counter,
        "char_class_counter": char_class_counter,
        "top_10_masks": top_10_masks,
        "guessable_passwords": guessable_passwords,
        "guessable_count": guessable_count,
        "user_pw_match": user_pw_match,
        "top_10_reused": top_10_reused,
        "length_violations": length_violations,
        "complexity_violations": complexity_violations,
    }

    cracked_chart = plot_cracked_pie_chart(total_hashes, total_cracked)
    length_chart = plot_password_length_chart(passwords)
    complexity_chart = plot_complexity_chart(complexity_scores)
    mask_chart = plot_top_masks_chart(mask_counter)
    reused_chart = plot_top_passwords_chart(pw_counter)

    charts = {
        "cracked_chart": cracked_chart,
        "length_chart": length_chart,
        "complexity_chart": complexity_chart,
        "mask_chart": mask_chart,
        "reused_chart": reused_chart
    }

    generate_html_report(metrics, charts, hibp_metrics, hibp_charts)


if __name__ == '__main__':
    app(prog_name='potpie')
