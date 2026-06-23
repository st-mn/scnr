import os
import json
import tempfile
import subprocess
import shutil
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SEVERITY_MAP = {
    'High': 'Critical',
    'Medium': 'High',
    'Low': 'Medium',
    'Informational': 'Low',
    'Optimization': 'Low'
}


def check_slither():
    return shutil.which('slither') is not None


def run_slither(sol_file):
    try:
        result = subprocess.run(
            ['slither', sol_file, '--json', '-'],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
        return None
    except subprocess.TimeoutExpired:
        raise RuntimeError('Slither timed out after 60 seconds')
    except json.JSONDecodeError as e:
        raise RuntimeError(f'Failed to parse Slither output: {str(e)}')
    except Exception as e:
        raise RuntimeError(f'Slither execution failed: {str(e)}')


def parse_slither_output(slither_json):
    vulnerabilities = []
    if not slither_json or 'results' not in slither_json:
        return vulnerabilities

    detectors = slither_json.get('results', {}).get('detectors', [])
    for det in detectors:
        impact = det.get('impact', 'Informational')
        severity = SEVERITY_MAP.get(impact, 'Low')

        elements = det.get('elements', [])
        locations = []
        for el in elements:
            name = el.get('name', '')
            if name:
                locations.append(name)

        location = ', '.join(locations[:3]) if locations else 'Contract level'
        if len(locations) > 3:
            location += f' (+{len(locations) - 3} more)'

        vulnerabilities.append({
            'title': det.get('check', 'Unknown check'),
            'severity': severity,
            'description': det.get('description', '').strip(),
            'location': location,
            'recommendation': det.get('recommendation', 'Review and fix the identified issue.').strip(),
            'confidence': det.get('confidence', 'Unknown'),
            'wiki': det.get('wiki', '')
        })

    return vulnerabilities


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'slither': check_slither(),
        'engine': 'slither'
    })


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({'success': False, 'error': 'No code provided'}), 400

    code = data['code']
    filename = data.get('filename', 'Contract.sol')

    if not check_slither():
        return jsonify({
            'success': False,
            'error': 'Slither not installed',
            'fallback': True
        }), 503

    tmp_dir = tempfile.mkdtemp()
    try:
        sol_path = os.path.join(tmp_dir, filename)
        with open(sol_path, 'w') as f:
            f.write(code)

        slither_output = run_slither(sol_path)
        vulnerabilities = parse_slither_output(slither_output)

        summary = {
            'totalIssues': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'Critical'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'High'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'Medium'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'Low'),
            'functionsAnalyzed': 0,
            'stateVariables': 0
        }

        if summary['critical'] > 0:
            status = 'critical'
        elif summary['high'] > 0:
            status = 'high'
        elif summary['medium'] > 0:
            status = 'medium'
        elif summary['low'] > 0:
            status = 'low'
        else:
            status = 'clean'

        return jsonify({
            'success': True,
            'engine': 'slither',
            'vulnerabilities': vulnerabilities,
            'summary': summary,
            'status': status
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'fallback': True
        }), 500
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == '__main__':
    port = int(os.environ.get('SCANNER_PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
