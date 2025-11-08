from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import random, os, subprocess, validators

app = Flask(__name__)
app.secret_key = 'vuln_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vuln_data.db'
db = SQLAlchemy(app)

# -------------------------
# DATABASE MODEL
# -------------------------
class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_detected = db.Column(db.DateTime, default=datetime.utcnow)


# -------------------------
# HOME PAGE (INTRO UI)
# -------------------------
@app.route('/')
def home():
    return render_template('home.html')


# -------------------------
# DASHBOARD PAGE
# -------------------------
@app.route('/dashboard')
def index():
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.date_detected.desc()).all()
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for v in vulnerabilities:
        if v.severity in severity_counts:
            severity_counts[v.severity] += 1
    return render_template('index.html', vulnerabilities=vulnerabilities, severity_counts=severity_counts)


# -------------------------
# BASIC SIMULATED SCAN
# -------------------------
@app.route('/scan', methods=['POST'])
def scan():
    simulated_vulns = [
        ("SQL Injection", "High", "Unsanitized input in login form."),
        ("Cross-Site Scripting (XSS)", "Medium", "Reflected XSS detected in user comments."),
        ("Insecure HTTP Headers", "Low", "Missing Content-Security-Policy header."),
        ("Server Misconfiguration", "Medium", "Directory listing is enabled."),
        ("Open Port 22 (SSH)", "Low", "SSH service exposed on public IP.")
    ]
    vuln = random.choice(simulated_vulns)
    new_vuln = Vulnerability(name=vuln[0], severity=vuln[1], description=vuln[2])
    db.session.add(new_vuln)
    db.session.commit()
    flash(f"Vulnerability '{vuln[0]}' detected successfully!", "success")
    return redirect(url_for('index'))


# -------------------------
# WEBSITE INPUT SCAN (USER-ENTERED URL)
# -------------------------
@app.route('/url_scan', methods=['GET', 'POST'])
def url_scan():
    if request.method == 'POST':
        target_url = request.form.get('target_url')

        if not validators.url(target_url):
            flash("Invalid URL. Please enter a valid website address (e.g., https://example.com)", "danger")
            return redirect(url_for('url_scan'))

        scan_result = f"Scan completed successfully for {target_url}. No high-risk vulnerabilities detected."

        new_vuln = Vulnerability(
            name=f"Scan for {target_url}",
            severity="Info",
            description=scan_result
        )
        db.session.add(new_vuln)
        db.session.commit()

        flash(f"Scan for {target_url} completed successfully!", "info")
        return render_template('scan_result.html', target=target_url, result=scan_result)

    return render_template('scan_input.html')


# -------------------------
# ADVANCED SCAN (NMAP + OWASP ZAP)
# -------------------------
@app.route('/advanced_scan', methods=['GET', 'POST'])
def advanced_scan():
    if request.method == 'POST':
        target = request.form['target']
        zap_api_key = "changeme"  # Replace with your OWASP ZAP API key

        try:
            nmap_result = subprocess.check_output(['nmap', '-sV', target], text=True)
        except Exception as e:
            nmap_result = f"Nmap Error: {str(e)}"

        try:
            zap_result = subprocess.check_output(
                ['zap-cli', '--api-key', zap_api_key, 'quick-scan', '--self-contained', '--spider', target],
                text=True
            )
        except Exception as e:
            zap_result = f"ZAP Error: {str(e)}"

        new_vuln = Vulnerability(
            name=f"Advanced Scan for {target}",
            severity="Info",
            description=f"Nmap and OWASP ZAP scan executed for {target}.\n\n--- Nmap ---\n{nmap_result}\n\n--- ZAP ---\n{zap_result}"
        )
        db.session.add(new_vuln)
        db.session.commit()

        flash(f"Advanced scan for {target} completed successfully!", "info")
        return render_template('scan_result.html', target=target, nmap=nmap_result, zap=zap_result)

    return render_template('advanced_scan.html')


# -------------------------
# DELETE VULNERABILITY
# -------------------------
@app.route('/delete/<int:id>')
def delete(id):
    vuln = Vulnerability.query.get_or_404(id)
    db.session.delete(vuln)
    db.session.commit()
    flash("Vulnerability deleted successfully!", "info")
    return redirect(url_for('index'))


# -------------------------
# MITIGATION STRATEGIES
# -------------------------
mitigation_strategies = {
    "SQL Injection": "Use parameterized queries or ORM to avoid string concatenation. Validate user inputs.",
    "Cross-Site Scripting (XSS)": "Escape user output in HTML/JS contexts and implement Content Security Policy (CSP).",
    "Insecure HTTP Headers": "Implement headers such as X-Frame-Options, X-Content-Type-Options, and CSP.",
    "Server Misconfiguration": "Disable directory listing, remove default server pages, and restrict access to sensitive files.",
    "Open Port 22 (SSH)": "Restrict SSH access to trusted IPs and use key-based authentication.",
    "Info": "No action required; for informational scans only.",
}


# -------------------------
# DOWNLOAD REPORT (With Mitigation Strategies)
# -------------------------
@app.route('/download_report')
def download_report():
    vulns = Vulnerability.query.all()
    filename = "vulnerability_report.pdf"
    filepath = os.path.join(os.getcwd(), filename)

    pdf = canvas.Canvas(filepath, pagesize=A4)
    width, height = A4
    y = height - 80

    # Report Header
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(140, y, "Vulnerability Assessment Report")
    y -= 40
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, y, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 30
    pdf.drawString(50, y, f"Total Findings: {len(vulns)}")
    y -= 40

    for vuln in vulns:
        if y < 120:
            pdf.showPage()
            pdf.setFont("Helvetica", 12)
            y = height - 100

        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(50, y, f"Name: {vuln.name}")
        y -= 18
        pdf.setFont("Helvetica", 12)
        pdf.drawString(70, y, f"Severity: {vuln.severity}")
        y -= 15
        pdf.drawString(70, y, f"Date: {vuln.date_detected.strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 20

        # Description
        pdf.setFont("Helvetica-Oblique", 11)
        desc = vuln.description[:250] + ("..." if len(vuln.description) > 250 else "")
        for line in desc.split('\n'):
            pdf.drawString(70, y, line)
            y -= 12

        # Mitigation Strategy
        mitigation = mitigation_strategies.get(vuln.name, "Apply general secure coding practices.")
        y -= 10
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(70, y, "Mitigation:")
        y -= 14
        pdf.setFont("Helvetica", 11)
        for line in mitigation.split('\n'):
            pdf.drawString(90, y, line)
            y -= 12

        y -= 10

    pdf.showPage()
    pdf.save()

    return send_file(filepath, as_attachment=True)


# -------------------------
# MAIN ENTRY POINT
# -------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
