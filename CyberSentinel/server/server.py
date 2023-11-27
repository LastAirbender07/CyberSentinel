from flask import Flask, request, jsonify
import subprocess, os, requests, json, hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import google.generativeai as palm
import time, glob
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"


@app.route('/')
def hello_world():
    return "Hello World!"

def calculate_sha256(file_path):
    chunk_size = 4096
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as file:
        while True:
            data = file.read(chunk_size)
            if not data:
                break
            sha256_hash.update(data)

    return sha256_hash.hexdigest()

############## Virus-total Scan files ##############
@app.route('/scan-file', methods=['POST'])
def scan_files():
    try:
        uploaded_file = request.files['file']

        if uploaded_file:
            filename = uploaded_file.filename
            filepath = os.path.join('path\server', filename)
            uploaded_file.save(filepath)
            file_hash = calculate_sha256(filepath)
            os.remove(filepath)
        else:
            return jsonify({'error': 'No file uploaded'})
    except Exception as e:
        return jsonify({'error': str(e)})

    api_key = 'XXXXX-XXXXX-XXXXX-XXXXX'
    url = 'https://www.virustotal.com/api/v3/files/{0}'.format(file_hash)
    headers = { "accept": "application/json", "content-type": "multipart/form-data", "x-apikey": api_key }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()

    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
    except json.decoder.JSONDecodeError:
        print('Error')
        return jsonify({'error': 'Invalid response from VirusTotal API.'}), 500

    malicious = result['data']['attributes']['last_analysis_stats']['malicious']
    suspicious = result['data']['attributes']['last_analysis_stats']['suspicious']
    if malicious + suspicious > 0:
        scan_result = jsonify({
            'Message': 'This file is malicious',
            'scan_id': result['data']['id'],
            'file_name': result['data']['attributes']['names'][0],
            'type': result['data']['attributes']['type_description'],
            'type_extension': result['data']['attributes']['type_extension'],
            'type_tag': result['data']['attributes']['type_tag'],
            'GUI Report': 'https://www.virustotal.com/gui/file/{0}/detection'.format(file_hash),
            'x-Full Scan': result
            })
        return scan_result
    else:
        scan_result = jsonify({
            'Message': 'This file is not malicious',
            'scan_id': result['data']['id'],
            'file_name': result['data']['attributes']['names'][0],
            'type': result['data']['attributes']['type_description'],
            'type_extension': result['data']['attributes']['type_extension'],
            'type_tag': result['data']['attributes']['type_tag'],
            'GUI Report': 'https://www.virustotal.com/gui/file/{0}/detection'.format(file_hash),
            'x-Full Scan': result
            })
        return scan_result
    
############## Virus-total Scan URL ##############
@app.route('/scan-url', methods=['POST'])
def scan_url():
    site = request.json.get('url')

    api_key = 'XXXXX-XXXXX-XXXXX-XXXXX'
    url = 'https://virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': site}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        result = json.loads(response.content)
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
    except json.decoder.JSONDecodeError:
        print('Error')
        return jsonify({'error': 'Invalid response from VirusTotal API.'}), 500

    if result['positives'] > 0:
        scan_result = jsonify({
            'Message': 'This site is malicious',
            'scan_id': result['scan_id'],
            'url': site,
            'scan_date': result['scan_date'],
            'positives': result['positives'],
            'total': result['total'],
            'scans': result['scans']})
        return scan_result
    else:
        scan_result = jsonify({
            'Message': 'This site is not malicious',
            'scan_id': result['scan_id'],
            'url': site,
            'scan_date': result['scan_date'],
            'positives': result['positives'],
            'total': result['total'],
            'scans': result['scans']})
        return scan_result
    
########### cve-id Info ###########
    
@app.route('/cve-tracker', methods=['POST'])
def cve_tracker():
    try:
        cve = request.json.get('url')
        api_key = 'XXXXX-XXXXX-XXXXX-XXXXX'
        url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}'
        params = {'apikey': api_key}
        
        response = requests.get(url, params=params).json()
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)})

########### sqlmap - SQL Injection Scanner ###########
@app.route('/sql-injection-scan', methods=['POST'])
def sql_injection_scan():
    try:
        url = request.json.get('url')
        forms = get_forms(url)
        results = []
        
        sql_tricks = [
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "admin' --",
            "admin' #",
            "admin'/*"
        ]

        if len(forms) == 0:
            return jsonify({'Output': 'No form found in the HTML'})

        for form in forms:
            details = form_details(form)
            vulnerabilities = []

            for trick in sql_tricks:
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["type"] == "hidden":
                        data[input_tag['name']] = trick
                    elif input_tag["type"] != "submit":
                        data[input_tag['name']] = f"test{trick}"

                if details["method"] == "post" or details["method"] == "POST":
                    res = s.post(url, data=data, verify=False)
                elif details["method"] == "get" or details["method"] == "GET":
                    res = s.get(url, params=data, verify=False)
                
                if vulnerable(res):
                    vulnerabilities.append({"trick": trick, "data": data})
            
            if vulnerabilities:
                results.append({"form_details": details, "vulnerabilities": vulnerabilities})
            else:
                results.append({"form_details": details, "vulnerabilities": "No SQL Injection Vulnerability"})

        return jsonify(results)
    
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)})

def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({
            "type": input_type, 
            "name" : input_name,
        })
        
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

def vulnerable(response):
    if response.status_code == 200:
        return True
    return False

########### Bandit - Python Security Scanner ###########
def run_bandit(filepath):
    try:
        result = subprocess.run(['bandit', '--format', 'json', filepath], capture_output=True, text=True)
        return json.loads(result.stdout)
    except Exception as e:
        return {'error': str(e)}

@app.route('/analyze-code1', methods=['POST'])
def analyze_code1():
    try:
        uploaded_file = request.files['file']

        if uploaded_file:
            filename = uploaded_file.filename
            filepath = os.path.join('path\server', filename)
            uploaded_file.save(filepath)
            analysis_result = run_bandit(filepath)
            os.remove(filepath)
            return jsonify({'results': analysis_result})
        else:
            return jsonify({'error': 'No file uploaded'})
    except Exception as e:
        return jsonify({'error': str(e)})
    
################## CPPcheck ####################

def run_cppcheck(filepath):
    try:
        output_file = os.path.splitext(filepath)[0] + "_cppcheck_output.txt"

        cppcheck_command = [
            'cppcheck',
            '--check-level=exhaustive',
            '--enable=all',
            '--platform=win64',
            '--output-file=' + output_file,
            filepath
        ]
        result = subprocess.run(cppcheck_command, capture_output=True, text=True)
        # print(f"cmd: {' '.join(cppcheck_command)}")
        # print(f"result: {result.stdout}")

        with open(output_file, 'r') as file:
            analysis_result = file.read()

        file.close()
        os.remove(output_file)
        
        return analysis_result
    except Exception as e:
        return {'error': str(e)}


@app.route('/analyze-code2', methods=['POST'])
def analyze_code2():
    try:
        uploaded_file = request.files['file']

        if uploaded_file:
            filename = uploaded_file.filename
            filepath = os.path.join('path\server', filename)
            uploaded_file.save(filepath)
            analysis_result = run_cppcheck(filepath)
            print(analysis_result)
            os.remove(filepath)
            return jsonify({'results': analysis_result})
        else:
            return jsonify({'error': 'No file uploaded'})
    except Exception as e:
        return jsonify({'error': str(e)})
    
################## Java Bugs ####################
@app.route('/analyze-code3', methods=['POST'])
def analyze_code3():
    try:
        uploaded_file = request.files['file']

        if uploaded_file:
            filename = uploaded_file.filename
            filepath = os.path.join('path\server', filename)
            uploaded_file.save(filepath)
            analysis_result, compilation_errors = run_spotbugs_analysis(filepath)
            if analysis_result == '':
                analysis_result = 'No bugs found'
            os.remove(filepath)
            return jsonify({'results': analysis_result, 'compilation_errors': compilation_errors})
        else:
            return jsonify({'error': 'No file uploaded'})
    except Exception as e:
        return jsonify({'error': str(e)})

def run_spotbugs_analysis(file_path):
    try:
        compilation_process = subprocess.run(['javac', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if compilation_process.returncode != 0:
            return '', compilation_process.stderr
        
        class_files_dir = "path\server"

        spotbugs_command = [
            'java',
            '-jar',
            'spotbugs/lib/spotbugs.jar',
            '-textui',
            '-effort:default',
            '-output',
            'spotbugs_results.json',
        ]

        class_files = glob.glob(os.path.join(class_files_dir, '**/*.class'), recursive=True)
        spotbugs_command.extend(class_files)

        subprocess.run(spotbugs_command, check=True)

        with open('spotbugs_results.json', 'r') as result_file:
            results = result_file.read()

        return results, None
    except subprocess.CalledProcessError as e:
        return '', f"Error running SpotBugs: {e}"
    finally:
        for class_file in class_files:
            os.remove(class_file)
        
        if os.path.exists('spotbugs_results.json'):
            os.remove('spotbugs_results.json')
    

################## XSS ####################
@app.route('/scan-xss', methods=['POST'])
def scan_xss():
    try:
        url = request.json.get('url')
        forms = get_forms(url)
        vulnerabilities = []

        payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert('XSS');</script>",
            "<<script>alert('XSS');//<</script>",
            "<sCripT>alert('XSS')</scRipt>",
            "<img src='/'>",
            "<img src=x onMouseOver=alert('XSS')>",
            "<svg/onload=eval('ale'+'rt')(`XSS${alert`XSS`}`)>",
            "<img src='nevermind' onerror=alert('XSS');>",
            "<< script>alert('XSS');//<</ script>",
            "<svg/onload=alert('XSS')>",
            "div.innerHTML = '<script>alert('XSS');</script>';",
            "<img src='aaa' onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<script>alert(document.cookie);</script>",
            "</Textarea/</Noscript/</Pre/</Xmp><Svg /Onload=confirm(document.domain)>",
            "<script src=//15.rs></script>",
            '''<IMG SRC="/" ONERROR="alert('XSS')">''',
            '''<IMG SRC="/" ONERROR=alert('XSS')>''',
            '''<img src=x onerror=alert('XSS')>''',
            '''<img src=x:alert(alt) onerror=eval(src) alt=xss>''',
            '''"><script>alert("XSS")</script>''',
            '''"><img src=x onerror=alert('XSS')>''',
            '''<div onmouseover="alert('XSS')">Move mouse here</div>''',
            '''<svg onload=alert('XSS')>''',
            '''<iframe src="javascript:alert('XSS');"></iframe>''',
            '''<svg/onload=eval(atob('YWxlcnQoJ0hBVCcsICcxJyk='))>''',
            '''<script>alert(String.fromCharCode(88, 83, 83))</script>''',
            '''"><img src=x onerror=confirm('XSS')>''',
            '''<svg onload="document.write('<img src=x onerror=alert(1)>')"></svg>''',
            '''<IMG SRC=javascript:alert('XSS')>''',
            '''<IMG SRC=javascript:alert(String.fromCharCode(88, 83, 83))>''',
            '''<IMG SRC=`javascript:alert("RSnake says, 'XSS'")`>''',
            '''<IMG """><SCRIPT>alert("XSS")</SCRIPT>">''',
            '''<IMG SRC=javascript:alert(String.fromCharCode(88, 83, 83))>''',
        ]
        
        for form in forms:
            form_details = get_form_details(form)
            form_vulnerabilities = []

            for payload in payloads:
                content = submit_form(form_details, url, payload).content.decode()
                if payload in content:
                    form_vulnerabilities.append(payload)
            
            if form_vulnerabilities:
                vulnerabilities.append({
                    'url' : url,
                    'form_details': form_details,
                    'vulnerabilities': form_vulnerabilities
                })

        if vulnerabilities:
            return jsonify(vulnerabilities)
        else:
            return jsonify({'message': 'No XSS vulnerabilities detected'})
    except Exception as e:
        return jsonify({'error': str(e)})
    
def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = [{"type": input_tag.attrs.get("type", "text"),
               "name": input_tag.attrs.get("name")} for input_tag in form.find_all("input")]
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {input["name"]: input.get("value", value) for input in inputs
            if input["type"] in ["text", "search"] and input.get("name")}
    
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)
    
################### Nikto Scanner ###################
@app.route('/nikto-scan', methods=['POST'])
def nikto_scan():
    try:
        url = request.json.get('url')
        secs = int(request.json.get('secs'))
        output = run_nikto(url, secs)
        return jsonify({'message': 'Nikto scan completed successfully', 'output': output}), 200
    except Exception as e:
        app.logger.error(f'Error during Nikto scan: {str(e)}')
        return jsonify({'error': 'Nikto scan failed'}), 500

def run_nikto(url, max_duration=180):
    try:
        nikto_path = os.path.join('nikto', 'program', 'nikto.pl')
        cmd = ['perl', nikto_path, '-h', url]
        app.logger.info(f"Running Nikto with command: {' '.join(cmd)}")

        start_time = time.time()
        process = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)

        output = ''
        while process.poll() is None:
            elapsed_time = time.time() - start_time
            if elapsed_time >= max_duration:
                process.terminate()
                app.logger.info(f"Scan terminated after {max_duration} seconds.")
                break

            line = process.stdout.readline()
            if line:
                output += line
                app.logger.info(line.strip())

        remaining_output = process.communicate()[0]
        output += remaining_output
        app.logger.info(remaining_output)

        return output

    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error running Nikto: {e.output}")
        return 'Nikto scan failed'
    
################### CSRF Scanner ###################
@app.route('/csrf-scan', methods=['POST'])
def csrf_scan():
    try:
        url = request.json.get('url')
        output = run_csrf(url)
        return jsonify({'output': output}), 200
    except Exception as e:
        app.logger.error(f'Error during CSRF scan: {str(e)}')
        return jsonify({'error': 'CSRF scan failed'}), 500

def run_csrf(url):
    main_py_path = "XSRFProbe\main.py"
    output_file = "path\server\output.txt" 
    log_folder = "xsrfprobe-output"
    command = f"python {main_py_path} -u {url} -v --malicious --crawl"

    try:
        with open(output_file, "w") as output:
            subprocess.run(command, shell=True, check=True, stdout=output, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(f"Error executing the command: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

    domain  = url.split("//")[1].split("/")[0]
    headers = ['www.', 'demo.']
    for i in headers:
        if i in domain :
            domain  = domain .replace(i,"")
            
    try:
        log_folder = os.path.join("xsrfprobe-output", domain)
        os.makedirs(log_folder, exist_ok=True)

        with open(output_file, "a") as output:
            log_files = [f for f in os.listdir(log_folder) if f.endswith(".log")]
            if "forms-tested.log" in log_files:
                log_files.remove("forms-tested.log")
            output.write("\n" + "=" * 80 + "\n")
            for log_file in log_files:
                log_file_path = os.path.join(log_folder, log_file)
                output.write(f"--- Log File: {log_file} ---\n")
                with open(log_file_path, "r") as log_content:
                    output.write(log_content.read())
                output.write("\n" + "=" * 80 + "\n")

        result = ''
        with open(output_file, 'r') as file:
            result = file.read().replace('<', '')
        file.close()
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error executing the command: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    
################### Bard API ###################

BARD_API_KEY = 'XXXXX-XXXXX-XXXXX-XXXXX'
palm.configure(api_key=BARD_API_KEY)
models = [m for m in palm.list_models() if 'generateText' in m.supported_generation_methods]
model = models[0].name
@app.route("/get_answer", methods=["POST"])
def get_answer():
    try:
        question = request.json.get('qn')
        question = "Consider yourself as a professional security assistant and answer my query : "  + question
        output = palm.generate_text(
        model=model,
        prompt=question,
        temperature=0,
        )
        output = output.result.replace('\n', '<br>')
        return jsonify({'reply': output})
    
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)