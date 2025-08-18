import typer
import string
import re
import importlib.metadata
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
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
        'upper': any(c.isupper() for c in pw),
        'lower': any(c.islower() for c in pw),
        'digit': any(c.isdigit() for c in pw),
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


def plot_cracked_pie(total_hashes, cracked_passwords, output_path='cracked_pie.png'):
    cracked = len(cracked_passwords)
    uncracked = total_hashes - cracked

    labels = ['Cracked', 'Uncracked']
    sizes = [cracked, uncracked]
    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    plt.title('Total Cracked Passwords')
    plt.savefig(output_path)
    plt.close()


def plot_password_length_distribution(passwords, output_path='length_distribution.png'):
    lengths = [len(p) for p in passwords]
    avg_len = np.mean(lengths)

    plt.figure(figsize=(10, 6))
    plt.hist(lengths, bins=range(min(lengths), max(lengths)+2), edgecolor='black')
    plt.axvline(avg_len, color='red', linestyle='dashed', linewidth=2, label=f'Avg Length: {avg_len:.2f}')
    plt.xlabel('Password Length')
    plt.ylabel('Frequency')
    plt.title('Password Length Distribution')
    plt.legend()
    plt.savefig(output_path)
    plt.close()


def plot_complexity(passwords, output_path='complexity_breakdown.png'):
    counter = Counter()
    total_score = 0

    for pw in passwords:
        flags = get_complexity_flags(pw)
        for k, v in flags.items():
            if v:
                counter[k] += 1
        total_score += sum(flags.values())

    labels = list(counter.keys())
    values = [counter[k] for k in labels]

    plt.figure(figsize=(8, 6))
    plt.bar(labels, values, color='skyblue')
    plt.ylabel('Number of Passwords')
    plt.title('Password Complexity Breakdown')
    plt.legend()
    plt.savefig(output_path)
    plt.close()


def plot_top_masks(mask_counter, top_n=10, output_path='top_masks.png'):
    top = dict(sorted(mask_counter.items(), key=lambda x: x[1], reverse=True)[:top_n])
    labels, values = zip(*top.items())

    plt.figure(figsize=(12, 6))
    plt.bar(labels, values)
    plt.title(f'Top {top_n} Password Masks')
    plt.ylabel('Frequency')
    plt.xlabel('Mask')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_top_passwords(pw_counter, top_n=10, output_path='top_passwords.png'):
    filtered = {pw: cnt for pw, cnt in pw_counter.items() if cnt > 1}
    top = dict(sorted(filtered.items(), key=lambda x: x[1], reverse=True)[:top_n])
    labels, values = zip(*top.items())

    plt.figure(figsize=(12, 6))
    plt.barh(labels, values, color='orange')
    plt.xlabel('Count')
    plt.title('Top Reused Passwords')
    plt.gca().invert_yaxis()  # Highest on top
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def generate_html_report(metrics, image_paths, output_path="./report/potpie_report.html"):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template("./potpie_template.html")

    rendered_html = template.render(metrics=metrics, image_paths=image_paths)

    with open(output_path, "w") as f:
        f.write(rendered_html)

    print(f"HTML report saved to {output_path}")


@app.command(no_args_is_help=True, help=help())
def main(
    min_length: int = typer.Option(..., '--length', '-l', help='Minimum password length (per policy)'),
    require_complexity: bool = typer.Option(False, '--complex', help='Password complexity is enabled (per policy)'),
    ntds: typer.FileText = typer.Option(..., '--ntds', '-n', help='Path to the NTDS.dit file'),
    potfile: typer.FileText = typer.Option(..., '--potfile', '-p', help='Path to the hashcat potfile'),
    debug: bool = typer.Option(False, '--debug', help='Enable [green]DEBUG[/] output')):

    init_logger(debug)

    cracked_passwords = {}
    for line in potfile:
        h, pw = line.strip().split(":", 1)
        cracked_passwords[h.lower()] = pw

    accounts = []
    for line in ntds:
        parts = line.strip().split(":")
        if len(parts) >= 4:
            username = parts[0]
            nt_hash = parts[3].lower()
            plaintext = cracked_passwords.get(nt_hash)
            accounts.append({
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

    # Password length analysis
    passwords = [acc['plaintext'] for acc in accounts if acc['plaintext'] is not None]
    avg_length = sum(len(pw) for pw in passwords) / len(passwords) if passwords else 0

    # Password complexity analysis
    complexity_scores = [sum(get_complexity_flags(pw).values()) for pw in passwords]
    avg_complexity = sum(complexity_scores) / len(complexity_scores)

    char_class_counter = Counter()
    for pw in passwords:
        flags = get_complexity_flags(pw)
        for k, v in flags.items():
            if v:
                char_class_counter[k] += 1

    # Password mask analysis
    mask_counter = Counter(get_mask(pw) for pw in passwords)
    top_masks = mask_counter.most_common(10)

    # Password policy violations
    policy_violations = []

    for acc in accounts:
        pw = acc["plaintext"]
        if not pw:
            continue
        too_short = len(pw) < min_length
        flags = get_complexity_flags(pw)
        classes_used = sum(flags.values())
        complexity_fail = require_complexity and classes_used < 3
        if too_short or complexity_fail:
            policy_violations.append({
                "username": acc["username"],
                "too_short": too_short,
                "complexity_fail": complexity_fail
            })
    
    # Username = password matches
    user_pw_match = sum(1 for acc in accounts if acc["plaintext"] and acc["plaintext"].lower() == acc["username"].lower())

    # Guessable password analysis
    common_patterns = [
        r"(spring|summer|fall|autumn|winter)\d{2,4}[!@#$%^&*]*",    # Season pattern
        r"(password|p@ssword|p@ssw0rd|passw0rd)\d*[!@#$%^&]*",  # "password" variants
        r"welcome\d*",  # welcome variants
        r"admin\d*",    # admin variants
        r"(letmein|changeme|qwerty|123456|12345678|1234567890)",    # known weak phrases
    ]

    combined_re = re.compile("|".join(common_patterns), re.IGNORECASE)
    guessable_passwords = [pw for pw in passwords if combined_re.search(pw)]
    guessable_count = len(guessable_passwords)

    # Top 10 common passwords
    pw_counter = Counter(pw for pw in passwords)
    reused_pw_list = [(pw, count) for pw, count in pw_counter.items() if count > 1]
    top_10_reused = sorted(reused_pw_list, key=lambda x: -x[1])[:10]

    # Generate charts
    plot_cracked_pie(total_hashes, cracked_passwords, './report/charts/cracked_pie.png')
    plot_password_length_distribution(passwords, './report/charts/length_distribution.png')
    plot_complexity(passwords, './report/charts/complexity_breakdown.png')
    plot_top_masks(mask_counter, 10, './report/charts/top_masks.png')
    plot_top_passwords(pw_counter, 10, './report/charts/top_passwords.png')

    # Generate HTML report
    metrics = {
        "total_hashes": total_hashes,
        "total_cracked": total_cracked,
        "total_unique_hashes": total_unique_hashes,
        "total_unique_cracked": total_unique_cracked,
        "avg_length": avg_length,
        "avg_complexity": avg_complexity,
        "char_class_counter": char_class_counter,
        "top_masks": top_masks,
        "policy_violations": policy_violations,
        "user_pw_match": user_pw_match,
        "guessable_passwords": guessable_passwords,
        "guessable_count": guessable_count,
        "top_10_reused": top_10_reused
    }

    image_paths = {
        "cracked_pie": "./charts/cracked_pie.png",
        "length_hist": "./charts/length_distribution.png",
        "complexity_bar": "./charts/complexity_breakdown.png",
        "mask_chart": "./charts/top_masks.png",
        "reused_passwords": "./charts/top_passwords.png"
    }

    generate_html_report(metrics, image_paths)


if __name__ == '__main__':
    app(prog_name='potpie')
